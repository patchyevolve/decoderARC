// ─────────────────────────────────────────────────────────────
//  ids_visualizer.cpp — Live terminal dashboard
//
//  Usage:
//    sudo ./ids_visualizer [interface] [bpf_filter]
//    sudo ./ids_visualizer eth0
//    sudo ./ids_visualizer eth0 "tcp port 80"
//
//  Requires: libpcap, ncurses
//  Build:    see CMakeLists.txt
// ─────────────────────────────────────────────────────────────
#include "include/ids.hpp"
#include "include/ids_capture.hpp"

#include <ncurses.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ── Shutdown ──────────────────────────────────────────────────
static std::atomic<bool> g_running{true};
static void sig_handler(int) { g_running = false; }

// ── Color pairs ───────────────────────────────────────────────
enum CP {
    CP_NORM = 1, CP_TITLE, CP_CYAN,
    CP_GREEN, CP_YELLOW, CP_RED, CP_MAGENTA,
    CP_DIM, CP_HEADER_BG, CP_GOOD, CP_WARN, CP_CRIT,
};

static bool g_has_colors = false;

static void init_colors() {
    g_has_colors = has_colors();
    if (!g_has_colors) return;

    start_color();
    // use_default_colors() enables -1 as "terminal default background".
    // Not all terminals support it; fall back to COLOR_BLACK if it fails.
    int bg = (use_default_colors() == OK) ? -1 : COLOR_BLACK;

    // All pairs use foreground-only coloring — no background color.
    // This ensures visibility on any terminal (dark, light, 8-color, 256-color).
    init_pair(CP_NORM,      COLOR_WHITE,   bg);
    init_pair(CP_TITLE,     COLOR_CYAN,    bg);   // header/status: bold cyan fg
    init_pair(CP_CYAN,      COLOR_CYAN,    bg);
    init_pair(CP_GREEN,     COLOR_GREEN,   bg);
    init_pair(CP_YELLOW,    COLOR_YELLOW,  bg);
    init_pair(CP_RED,       COLOR_RED,     bg);
    init_pair(CP_MAGENTA,   COLOR_MAGENTA, bg);
    init_pair(CP_DIM,       COLOR_WHITE,   bg);
    init_pair(CP_HEADER_BG, COLOR_CYAN,    bg);
    init_pair(CP_GOOD,      COLOR_GREEN,   bg);
    init_pair(CP_WARN,      COLOR_YELLOW,  bg);
    init_pair(CP_CRIT,      COLOR_RED,     bg);
}

// ── Alert ring ────────────────────────────────────────────────
struct AlertEntry {
    std::string time_str, decision, source, attack_class;
    float confidence = 0.f;
};

struct AlertRing {
    std::deque<AlertEntry> items;
    std::mutex mu;
    static constexpr size_t kMax = 500;
    void push(AlertEntry e) {
        std::lock_guard<std::mutex> lk(mu);
        items.push_front(std::move(e));
        if (items.size() > kMax) items.pop_back();
    }
    std::vector<AlertEntry> snapshot(size_t n) {
        std::lock_guard<std::mutex> lk(mu);
        std::vector<AlertEntry> out;
        size_t take = std::min(n, items.size());
        out.reserve(take);
        for (size_t i = 0; i < take; ++i) out.push_back(items[i]);
        return out;
    }
};

// ── EPS tracker ───────────────────────────────────────────────
struct EpsTracker {
    std::atomic<uint64_t> count{0}, eps{0};
    uint64_t last_count = 0;
    std::chrono::steady_clock::time_point last_time = std::chrono::steady_clock::now();
    void tick() {
        auto now = std::chrono::steady_clock::now();
        float dt = std::chrono::duration<float>(now - last_time).count();
        if (dt >= 1.f) {
            uint64_t c = count.load();
            eps = static_cast<uint64_t>((c - last_count) / dt);
            last_count = c; last_time = now;
        }
    }
};

// ── Sparkline (ASCII, 60 samples) ────────────────────────────
struct Sparkline {
    std::deque<uint64_t> samples;
    static constexpr size_t kLen = 60;
    void push(uint64_t v) {
        samples.push_back(v);
        if (samples.size() > kLen) samples.pop_front();
    }
    // Draw a filled bar chart using ASCII pipe chars
    void draw(WINDOW* w, int y, int x, int width, int height) const {
        if (samples.empty()) return;
        uint64_t mx = 1;
        for (auto s : samples) mx = std::max(mx, s);
        int n = static_cast<int>(samples.size());
        int start = std::max(0, n - width);
        for (int i = start; i < n; ++i) {
            float frac = float(samples[i]) / float(mx);
            int col = x + (i - start);
            int filled = static_cast<int>(frac * height);
            filled = std::max(0, std::min(filled, height));
            for (int row = 0; row < height; ++row) {
                int level = height - 1 - row;  // 0 = bottom
                if (level < filled) {
                    // colour gradient: green→yellow→red by height
                    int cp = (level < height / 3) ? CP_GREEN
                           : (level < 2 * height / 3) ? CP_YELLOW : CP_RED;
                    wattron(w, COLOR_PAIR(cp) | A_BOLD);
                    mvwaddch(w, y + row, col, '|');
                    wattroff(w, COLOR_PAIR(cp) | A_BOLD);
                } else {
                    wattron(w, A_DIM);
                    mvwaddch(w, y + row, col, '.');
                    wattroff(w, A_DIM);
                }
            }
        }
    }
};

// ── Helpers ───────────────────────────────────────────────────
static std::string fmt_k(uint64_t v) {
    if (v >= 1000000) return std::to_string(v / 1000000) + "M";
    if (v >= 1000)    return std::to_string(v / 1000) + "k";
    return std::to_string(v);
}

static std::string fmt_us(float us) {
    char buf[24];
    if (us >= 1000.f) snprintf(buf, sizeof(buf), "%.1fms", us / 1000.f);
    else              snprintf(buf, sizeof(buf), "%.0fus", us);
    return buf;
}

static std::string now_str() {
    auto t  = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(t);
    struct tm tm_buf; localtime_r(&tt, &tm_buf);
    char buf[16]; strftime(buf, sizeof(buf), "%H:%M:%S", &tm_buf);
    return buf;
}

// Draw a horizontal bar: label | filled chars | value
static void draw_bar(WINDOW* w, int y, int x, int width,
                     float fraction, int cp_fill) {
    int filled = static_cast<int>(std::max(0.f, std::min(1.f, fraction)) * width);
    wattron(w, COLOR_PAIR(cp_fill) | A_BOLD);
    for (int i = 0; i < filled; ++i)        mvwaddch(w, y, x + i, '=');
    wattroff(w, COLOR_PAIR(cp_fill) | A_BOLD);
    wattron(w, A_DIM);
    for (int i = filled; i < width; ++i)    mvwaddch(w, y, x + i, '-');
    wattroff(w, A_DIM);
}

// Bordered panel with coloured title
static void draw_panel(WINDOW* w, const char* title, int title_cp) {
    box(w, 0, 0);
    if (title && title[0]) {
        wattron(w, COLOR_PAIR(title_cp) | A_BOLD);
        mvwprintw(w, 0, 2, " %s ", title);
        wattroff(w, COLOR_PAIR(title_cp) | A_BOLD);
    }
}

// ─────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::string iface  = (argc > 1) ? argv[1] : "";
    std::string filter = (argc > 2) ? argv[2] : "ip";

    if (iface.empty()) {
        auto ifaces = ids::PacketCapture::list_interfaces();
        if (ifaces.empty()) { fprintf(stderr, "No interfaces. Run as root?\n"); return 1; }
        iface = ifaces[0];
    }

    // ── Pipeline config ───────────────────────────────────────
    ids::IDSConfig cfg;
    cfg.gate.gate_threshold         = 0.35f;
    cfg.write_policy.memory_write_gate  = 0.45f;
    cfg.write_policy.write_on_block     = true;
    cfg.force_gate.force_local          = 0.85f;
    cfg.force_gate.force_on_rule_match  = true;
    cfg.panic.panic_threshold           = 500;
    cfg.telemetry.latency_tracking      = true;
    cfg.telemetry.drift_series          = true;
    auto pipeline = std::make_unique<ids::IDS>(cfg);

    // ── Shared state ──────────────────────────────────────────
    AlertRing  alerts;
    EpsTracker eps;
    Sparkline  sparkline;

    auto decision_str = [](ids::Decision d) -> const char* {
        switch (d) {
        case ids::Decision::Log:      return "LOG";
        case ids::Decision::Alert:    return "ALERT";
        case ids::Decision::Block:    return "BLOCK";
        case ids::Decision::Escalate: return "ESCALATE";
        default:                      return "IGNORE";
        }
    };

    auto make_entry = [&](const ids::Alert& a) {
        AlertEntry e;
        e.time_str    = now_str();
        e.decision    = decision_str(a.trace.final_decision);
        e.source      = a.source;
        e.attack_class= (a.attack_class.empty() || a.attack_class == "none") ? "-" : a.attack_class;
        e.confidence  = a.confidence;
        alerts.push(e);
    };

    pipeline->on_alert   ([&](const ids::Alert& a){ make_entry(a); });
    pipeline->on_block   ([&](const std::string&)  { /* covered by on_alert */ });
    pipeline->on_escalate([&](const ids::Alert& a){ make_entry(a); });

    // ── Capture ───────────────────────────────────────────────
    ids::PacketCapture capture(iface, filter);
    capture.on_event([&](const ids::Event& ev) {
        pipeline->ingest(ev);
        eps.count++;
    });
    if (!capture.start()) {
        fprintf(stderr, "Capture failed on '%s': %s\nTry: sudo ./ids_visualizer <iface>\n",
                iface.c_str(), capture.stats().last_error.c_str());
        return 1;
    }

    // ── ncurses ───────────────────────────────────────────────
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    initscr(); cbreak(); noecho(); curs_set(0);
    nodelay(stdscr, true); keypad(stdscr, true);
    init_colors();

    // ── Layout builder ────────────────────────────────────────
    // Row map:
    //  0        : header (1 row, full width, filled bg)
    //  1..5     : metrics panel (5 rows)
    //  6..13    : middle row — sparkline (left) | pipeline state (right)
    //  14..end-1: alert feed
    //  end      : status bar
    auto make_layout = [&]() {
        int rows, cols;
        getmaxyx(stdscr, rows, cols);
        int mid      = cols * 3 / 5;          // sparkline gets 60% width
        int right_w  = cols - mid;
        int feed_h   = std::max(5, rows - 15);
        WINDOW* wh   = newwin(1,      cols,    0,   0);
        WINDOW* wm   = newwin(5,      cols,    1,   0);
        WINDOW* wsp  = newwin(8,      mid,     6,   0);
        WINDOW* wst  = newwin(8,      right_w, 6,   mid);
        WINDOW* wf   = newwin(feed_h, cols,    14,  0);
        WINDOW* wsb  = newwin(1,      cols,    rows-1, 0);
        return std::make_tuple(wh, wm, wsp, wst, wf, wsb,
                               rows, cols, mid, right_w, feed_h);
    };

    auto [wh, wm, wsp, wst, wf, wsb,
          rows, cols, mid, right_w, feed_h] = make_layout();

    uint64_t frame = 0;
    auto last_spark = std::chrono::steady_clock::now();

    // ── Render loop ───────────────────────────────────────────
    while (g_running.load()) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;
        if (ch == KEY_RESIZE) {
            delwin(wh); delwin(wm); delwin(wsp);
            delwin(wst); delwin(wf); delwin(wsb);
            clear(); refresh();
            auto [a,b,c,d,e,f,r,co,md,rw,fh] = make_layout();
            wh=a; wm=b; wsp=c; wst=d; wf=e; wsb=f;
            rows=r; cols=co; mid=md; right_w=rw; feed_h=fh;
        }

        eps.tick();
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<float>(now - last_spark).count() >= 1.f) {
            sparkline.push(eps.eps.load());
            last_spark = now;
        }

        const auto& mx  = pipeline->metrics();
        const auto& hx  = pipeline->health();
        auto lat         = pipeline->latency_stats();
        auto gs          = pipeline->global_state();
        auto campaigns   = pipeline->active_campaigns();
        auto cap         = capture.stats().snapshot();

        // ── Header bar ───────────────────────────────────────
        werase(wh);
        wattron(wh, COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvwprintw(wh, 0, 1, " IDS Live  iface:%-8s  filter:%-16s  %s",
                  iface.c_str(),
                  filter.empty() ? "none" : filter.c_str(),
                  now_str().c_str());
        wattroff(wh, COLOR_PAIR(CP_TITLE) | A_BOLD);
        // Mode badge — use A_REVERSE only if colors available, else just bold
        const char* mode_str = hx.panic_mode ? " PANIC " : " LIVE ";
        int cp_mode = hx.panic_mode ? CP_CRIT : CP_GOOD;
        int badge_x = cols - (int)strlen(mode_str) - 1;
        if (g_has_colors) {
            wattron(wh, COLOR_PAIR(cp_mode) | A_BOLD | A_REVERSE);
            mvwprintw(wh, 0, badge_x, "%s", mode_str);
            wattroff(wh, COLOR_PAIR(cp_mode) | A_BOLD | A_REVERSE);
        } else {
            wattron(wh, A_BOLD);
            mvwprintw(wh, 0, badge_x, "%s", mode_str);
            wattroff(wh, A_BOLD);
        }
        wnoutrefresh(wh);

        // ── Metrics panel ─────────────────────────────────────
        werase(wm);
        draw_panel(wm, "Metrics", CP_CYAN);

        struct Cell { const char* lbl; uint64_t val; int cp; bool pct; };
        uint64_t reas_pct = mx.events_total.load() > 0
            ? mx.reasoning_calls.load() * 100 / mx.events_total.load() : 0;
        Cell cells[] = {
            {"ev/s",   eps.eps.load(),              CP_GREEN,   false},
            {"total",  mx.events_total.load(),      CP_CYAN,    false},
            {"alerts", mx.alerts_total.load(),      CP_YELLOW,  false},
            {"blocks", mx.blocks_total.load(),      CP_RED,     false},
            {"escal",  mx.escalations_total.load(), CP_MAGENTA, false},
            {"reas%",  reas_pct,                    CP_YELLOW,  true },
            {"faults", mx.faults_total.load(),      CP_RED,     false},
            {"camps",  (uint64_t)campaigns.size(),  CP_MAGENTA, false},
        };
        int cw = std::max(8, (cols - 2) / 8);
        for (int i = 0; i < 8; ++i) {
            int cx = 1 + i * cw;
            // Label
            wattron(wm, A_DIM);
            mvwprintw(wm, 1, cx, "%-*s", cw - 1, cells[i].lbl);
            wattroff(wm, A_DIM);
            // Value
            std::string vs = fmt_k(cells[i].val) + (cells[i].pct ? "%" : "");
            wattron(wm, COLOR_PAIR(cells[i].cp) | A_BOLD);
            mvwprintw(wm, 2, cx, "%-*s", cw - 1, vs.c_str());
            wattroff(wm, COLOR_PAIR(cells[i].cp) | A_BOLD);
        }
        // Latency row
        wattron(wm, A_DIM);
        mvwprintw(wm, 3, 1,
            "L0:%-7s L1:%-7s Retr:%-7s Reas:%-7s Tot:%-7s",
            fmt_us(lat.l0_avg_us).c_str(),
            fmt_us(lat.l1_avg_us).c_str(),
            fmt_us(lat.retrieval_avg_us).c_str(),
            fmt_us(lat.reasoning_avg_us).c_str(),
            fmt_us(lat.total_avg_us).c_str());
        wattroff(wm, A_DIM);
        // Drift / anomaly / packet row
        wattron(wm, A_DIM);
        mvwprintw(wm, 4, 1,
            "Drift:%-5.2f  Anomaly:%-5.2f  MemWr:%-6s  Pkts:%-7s  Drops:%s",
            gs.drift_score, gs.anomaly_history,
            fmt_k(mx.memory_writes.load()).c_str(),
            fmt_k(cap.packets_captured).c_str(),
            fmt_k(cap.packets_dropped).c_str());
        wattroff(wm, A_DIM);
        wnoutrefresh(wm);

        // ── Sparkline panel ───────────────────────────────────
        werase(wsp);
        draw_panel(wsp, "Throughput  ev/s", CP_GREEN);
        sparkline.draw(wsp, 1, 1, mid - 2, 5);
        // Peak label top-right
        if (!sparkline.samples.empty()) {
            uint64_t pk = *std::max_element(sparkline.samples.begin(),
                                             sparkline.samples.end());
            wattron(wsp, COLOR_PAIR(CP_GREEN));
            mvwprintw(wsp, 1, mid - 9, "pk:%-5s", fmt_k(pk).c_str());
            wattroff(wsp, COLOR_PAIR(CP_GREEN));
        }
        // Current EPS bottom-left
        wattron(wsp, COLOR_PAIR(CP_GREEN) | A_BOLD);
        mvwprintw(wsp, 6, 1, " %s ev/s ", fmt_k(eps.eps.load()).c_str());
        wattroff(wsp, COLOR_PAIR(CP_GREEN) | A_BOLD);
        wnoutrefresh(wsp);

        // ── Pipeline state panel ──────────────────────────────
        werase(wst);
        draw_panel(wst, "Pipeline", CP_CYAN);
        int bw = right_w - 14;  // bar width

        // Drift
        {
            int cp = gs.drift_score > 5.f ? CP_CRIT : gs.drift_score > 2.f ? CP_WARN : CP_GOOD;
            wattron(wst, A_DIM); mvwprintw(wst, 1, 1, "Drift  "); wattroff(wst, A_DIM);
            draw_bar(wst, 1, 8, bw, std::min(1.f, gs.drift_score / 10.f), cp);
            wattron(wst, COLOR_PAIR(cp) | A_BOLD);
            mvwprintw(wst, 1, 8 + bw + 1, "%.2f", gs.drift_score);
            wattroff(wst, COLOR_PAIR(cp) | A_BOLD);
        }
        // Anomaly
        {
            int cp = gs.anomaly_history > 0.7f ? CP_CRIT : gs.anomaly_history > 0.4f ? CP_WARN : CP_GOOD;
            wattron(wst, A_DIM); mvwprintw(wst, 2, 1, "Anomaly"); wattroff(wst, A_DIM);
            draw_bar(wst, 2, 8, bw, gs.anomaly_history, cp);
            wattron(wst, COLOR_PAIR(cp) | A_BOLD);
            mvwprintw(wst, 2, 8 + bw + 1, "%.2f", gs.anomaly_history);
            wattroff(wst, COLOR_PAIR(cp) | A_BOLD);
        }
        // Memory write ratio
        {
            uint64_t mw = mx.memory_writes.load();
            uint64_t et = std::max(uint64_t(1), mx.events_total.load());
            float ratio = float(mw) / float(et);
            wattron(wst, A_DIM); mvwprintw(wst, 3, 1, "MemWr  "); wattroff(wst, A_DIM);
            draw_bar(wst, 3, 8, bw, ratio, CP_GREEN);
            wattron(wst, A_DIM);
            mvwprintw(wst, 3, 8 + bw + 1, "%3d%%", (int)(ratio * 100));
            wattroff(wst, A_DIM);
        }
        // Reasoning load
        {
            float rload = mx.events_total.load() > 0
                ? float(mx.reasoning_calls.load()) / float(mx.events_total.load()) : 0.f;
            int cp = rload > 0.8f ? CP_WARN : CP_CYAN;
            wattron(wst, A_DIM); mvwprintw(wst, 4, 1, "Reas   "); wattroff(wst, A_DIM);
            draw_bar(wst, 4, 8, bw, rload, cp);
            wattron(wst, A_DIM);
            mvwprintw(wst, 4, 8 + bw + 1, "%3d%%", (int)(rload * 100));
            wattroff(wst, A_DIM);
        }
        // Campaigns
        wattron(wst, A_DIM);
        mvwprintw(wst, 5, 1, "Campaigns: %zu", campaigns.size());
        wattroff(wst, A_DIM);
        {
            int crow = 6;
            int name_w = std::max(4, bw - 2);
            for (size_t i = 0; i < campaigns.size() && crow < 7; ++i, ++crow) {
                std::string cls = campaigns[i].attack_class.substr(0, name_w);
                wattron(wst, COLOR_PAIR(CP_MAGENTA) | A_BOLD);
                mvwprintw(wst, crow, 2, "> %-*s %4u", name_w, cls.c_str(),
                          campaigns[i].event_count);
                wattroff(wst, COLOR_PAIR(CP_MAGENTA) | A_BOLD);
            }
        }
        wnoutrefresh(wst);

        // ── Alert feed ────────────────────────────────────────
        werase(wf);
        draw_panel(wf, "Alert Feed", CP_YELLOW);

        // Column header
        wattron(wf, A_BOLD | A_UNDERLINE);
        mvwprintw(wf, 1, 1, "%-8s %-9s %-16s %-22s %5s",
                  "Time", "Decision", "Source", "Class", "Conf");
        wattroff(wf, A_BOLD | A_UNDERLINE);

        auto feed = alerts.snapshot(static_cast<size_t>(feed_h - 3));
        for (int i = 0; i < (int)feed.size(); ++i) {
            const auto& a = feed[i];
            int cp = CP_NORM;
            if      (a.decision == "ESCALATE") cp = CP_MAGENTA;
            else if (a.decision == "BLOCK")    cp = CP_RED;
            else if (a.decision == "ALERT")    cp = CP_YELLOW;
            else if (a.decision == "LOG")      cp = CP_CYAN;

            // Alternate row dimming for readability
            if (i % 2 == 1) wattron(wf, A_DIM);
            wattron(wf, COLOR_PAIR(cp));
            mvwprintw(wf, 2 + i, 1, "%-8s %-9s %-16s %-22s %5.2f",
                      a.time_str.c_str(),
                      a.decision.c_str(),
                      a.source.substr(0, 15).c_str(),
                      a.attack_class.substr(0, 21).c_str(),
                      a.confidence);
            wattroff(wf, COLOR_PAIR(cp));
            if (i % 2 == 1) wattroff(wf, A_DIM);
        }
        wnoutrefresh(wf);

        // ── Status bar ────────────────────────────────────────
        werase(wsb);
        wattron(wsb, COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvwprintw(wsb, 0, 1,
            "[q] quit  |  frame %-6lu  |  cap: %-6s pkts  |  drops: %-5s  |  %s",
            frame,
            fmt_k(cap.packets_captured).c_str(),
            fmt_k(cap.packets_dropped).c_str(),
            hx.panic_mode ? "!! PANIC MODE !!" : "normal");
        wattroff(wsb, COLOR_PAIR(CP_TITLE) | A_BOLD);
        wnoutrefresh(wsb);

        doupdate();
        ++frame;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // ── Cleanup ───────────────────────────────────────────────
    capture.stop();
    delwin(wh); delwin(wm); delwin(wsp);
    delwin(wst); delwin(wf); delwin(wsb);
    endwin();

    const auto& mx = pipeline->metrics();
    auto lat = pipeline->latency_stats();
    printf("\n=== Session Summary ===\n");
    printf("  Events      : %lu\n", mx.events_total.load());
    printf("  Alerts      : %lu\n", mx.alerts_total.load());
    printf("  Blocks      : %lu\n", mx.blocks_total.load());
    printf("  Escalations : %lu\n", mx.escalations_total.load());
    printf("  Faults      : %lu\n", mx.faults_total.load());
    printf("  L0 avg      : %s\n",  fmt_us(lat.l0_avg_us).c_str());
    printf("  Total avg   : %s\n",  fmt_us(lat.total_avg_us).c_str());
    return 0;
}
