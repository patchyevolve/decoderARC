#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <numeric>
#include <random>
#include <vector>

namespace ids {

// ─── Simple matrix (row-major, owned storage) ────────────────
struct Matrix {
    size_t rows = 0, cols = 0;
    std::vector<float> data;

    Matrix() = default;
    Matrix(size_t r, size_t c, float init = 0.f)
        : rows(r), cols(c), data(r * c, init) {}

    float& at(size_t r, size_t c) { return data[r * cols + c]; }
    float  at(size_t r, size_t c) const { return data[r * cols + c]; }

    float* row(size_t r) { return data.data() + r * cols; }
    const float* row(size_t r) const { return data.data() + r * cols; }

    Matrix clone() const { return *this; }

    // Xavier init
    void xavier(size_t fan_in, std::minstd_rand& rng) {
        float scale = std::sqrt(2.f / static_cast<float>(fan_in));
        std::uniform_real_distribution<float> dist(-scale, scale);
        for (auto& v : data) v = dist(rng);
    }

    Matrix T() const {
        Matrix m(cols, rows);
        for (size_t r = 0; r < rows; ++r)
            for (size_t c = 0; c < cols; ++c)
                m.at(c, r) = at(r, c);
        return m;
    }
};

inline Matrix operator+(const Matrix& a, const Matrix& b) {
    Matrix c(a.rows, a.cols);
    for (size_t i = 0; i < c.data.size(); ++i) c.data[i] = a.data[i] + b.data[i];
    return c;
}

inline Matrix operator-(const Matrix& a, const Matrix& b) {
    Matrix c(a.rows, a.cols);
    for (size_t i = 0; i < c.data.size(); ++i) c.data[i] = a.data[i] - b.data[i];
    return c;
}

inline Matrix mul(const Matrix& a, const Matrix& b) {
    Matrix c(a.rows, b.cols, 0.f);
    for (size_t i = 0; i < a.rows; ++i)
        for (size_t k = 0; k < a.cols; ++k) {
            float aik = a.at(i, k);
            if (aik == 0.f) continue;
            for (size_t j = 0; j < b.cols; ++j)
                c.at(i, j) += aik * b.at(k, j);
        }
    return c;
}

// ─── Activations ──────────────────────────────────────────────
inline float relu(float x) { return x > 0.f ? x : 0.f; }
inline float d_relu(float x) { return x > 0.f ? 1.f : 0.f; }
inline float sigmoid(float x) { return 1.f / (1.f + std::exp(-x)); }

struct Layer {
    Matrix w, b;
    std::vector<float> (*act)(const std::vector<float>&) = nullptr;
    std::vector<float> (*d_act)(const std::vector<float>&) = nullptr;

    // Cache for backprop
    std::vector<float> input_cache;
    std::vector<float> pre_act_cache;

    Layer() = default;

    Layer(size_t in_dim, size_t out_dim,
          std::vector<float> (*activation)(const std::vector<float>&) = nullptr,
          std::vector<float> (*d_activation)(const std::vector<float>&) = nullptr,
          std::minstd_rand* rng = nullptr)
        : w(out_dim, in_dim), b(out_dim, 1),
          act(activation), d_act(d_activation) {
        if (rng) w.xavier(in_dim, *rng);
    }

    std::vector<float> forward(const std::vector<float>& input) {
        input_cache = input;
        std::vector<float> out(w.rows, b.at(0, 0));
        for (size_t i = 0; i < w.rows; ++i)
            for (size_t j = 0; j < w.cols; ++j)
                out[i] += w.at(i, j) * input[j];
        pre_act_cache = out;
        if (act) out = act(out);
        return out;
    }

    // Backprop: given dL/doutput, return dL/dinput
    std::vector<float> backward(const std::vector<float>& d_output,
                                Matrix* d_w, Matrix* d_b) {
        std::vector<float> d_pre = d_output;
        if (d_act) d_pre = d_act(pre_act_cache);

        // dL/dw = d_output * input^T
        if (d_w) {
            d_w->rows = w.rows; d_w->cols = w.cols;
            d_w->data.resize(w.rows * w.cols, 0.f);
            for (size_t i = 0; i < w.rows; ++i)
                for (size_t j = 0; j < w.cols; ++j)
                    d_w->at(i, j) = d_pre[i] * input_cache[j];
        }
        if (d_b) {
            d_b->rows = b.rows; d_b->cols = b.cols;
            d_b->data = d_pre;
        }

        // dL/dinput = W^T * d_pre
        std::vector<float> d_input(w.cols, 0.f);
        for (size_t j = 0; j < w.cols; ++j)
            for (size_t i = 0; i < w.rows; ++i)
                d_input[j] += w.at(i, j) * d_pre[i];
        return d_input;
    }
};

// ─── SGD optimizer ────────────────────────────────────────────
struct SGD {
    float lr;
    SGD(float lr = 0.01f) : lr(lr) {}

    void step(Layer& layer, const Matrix& d_w, const Matrix& d_b) {
        for (size_t i = 0; i < layer.w.data.size(); ++i)
            layer.w.data[i] -= lr * d_w.data[i];
        for (size_t i = 0; i < layer.b.data.size(); ++i)
            layer.b.data[i] -= lr * d_b.data[i];
    }
};

inline std::vector<float> vec_relu(const std::vector<float>& v) {
    std::vector<float> r(v.size());
    for (size_t i = 0; i < v.size(); ++i) r[i] = relu(v[i]);
    return r;
}
inline std::vector<float> vec_d_relu(const std::vector<float>& v) {
    std::vector<float> r(v.size());
    for (size_t i = 0; i < v.size(); ++i) r[i] = d_relu(v[i]);
    return r;
}
inline std::vector<float> vec_id(const std::vector<float>& v) { return v; }
inline std::vector<float> vec_d_id(const std::vector<float>& v) {
    return std::vector<float>(v.size(), 1.f);
}

// ─── 3-layer Autoencoder ──────────────────────────────────────
class Autoencoder {
public:
    Autoencoder(size_t input_dim = 40, size_t hidden = 16, size_t bottleneck = 8,
                float lr = 0.01f)
        : enc1_(input_dim, hidden, vec_relu, vec_d_relu, &rng_),
          enc2_(hidden, bottleneck, vec_relu, vec_d_relu, &rng_),
          dec1_(bottleneck, hidden, vec_relu, vec_d_relu, &rng_),
          dec2_(hidden, input_dim, vec_id, vec_d_id, &rng_),
          opt_(lr), input_dim_(input_dim) {}

    std::vector<float> encode(const std::vector<float>& x) {
        return enc2_.forward(enc1_.forward(x));
    }

    std::vector<float> decode(const std::vector<float>& z) {
        return dec2_.forward(dec1_.forward(z));
    }

    std::vector<float> reconstruct(const std::vector<float>& x) {
        return decode(encode(x));
    }

    float mse_loss(const std::vector<float>& x) {
        auto recon = reconstruct(x);
        float loss = 0.f;
        for (size_t i = 0; i < x.size(); ++i) {
            float d = recon[i] - x[i];
            loss += d * d;
        }
        return loss / static_cast<float>(x.size());
    }

    float train_step(const std::vector<float>& x) {
        // Forward
        auto h1 = enc1_.forward(x);
        auto h2 = enc2_.forward(h1);
        auto h3 = dec1_.forward(h2);
        auto h4 = dec2_.forward(h3); // reconstruction

        // MSE loss
        float loss = 0.f;
        for (size_t i = 0; i < x.size(); ++i) {
            float d = h4[i] - x[i];
            loss += d * d;
        }
        loss /= static_cast<float>(x.size());

        // Backward — decoder 2
        std::vector<float> d_out(x.size());
        for (size_t i = 0; i < x.size(); ++i) d_out[i] = 2.f * (h4[i] - x[i]) / x.size();
        Matrix d_w4, d_b4;
        auto d_h3 = dec2_.backward(d_out, &d_w4, &d_b4);

        // Decoder 1
        Matrix d_w3, d_b3;
        auto d_h2 = dec1_.backward(d_h3, &d_w3, &d_b3);

        // Encoder 2
        Matrix d_w2, d_b2;
        auto d_h1 = enc2_.backward(d_h2, &d_w2, &d_b2);

        // Encoder 1
        Matrix d_w1, d_b1;
        enc1_.backward(d_h1, &d_w1, &d_b1);

        // Gradient step
        opt_.step(dec2_, d_w4, d_b4);
        opt_.step(dec1_, d_w3, d_b3);
        opt_.step(enc2_, d_w2, d_b2);
        opt_.step(enc1_, d_w1, d_b1);

        return loss;
    }

    // Train on a batch of embeddings
    float train_batch(const std::vector<std::vector<float>>& batch, size_t epochs = 1) {
        float total_loss = 0.f;
        size_t count = 0;
        for (size_t e = 0; e < epochs; ++e)
            for (const auto& x : batch) {
                total_loss += train_step(x);
                count++;
            }
        return count > 0 ? total_loss / static_cast<float>(count) : 0.f;
    }

    // Online/incremental update: single SGD step at small learning rate
    // Used during production ingest on confirmed-benign events.
    // Keeps the model adapted to gradual traffic drift.
    float online_update(const std::vector<float>& x, float lr = 0.001f) {
        float saved = opt_.lr;
        opt_.lr = lr;
        float loss = train_step(x);
        opt_.lr = saved;
        return loss;
    }

    // Anomaly score: normalized reconstruction error
    float anomaly_score(const std::vector<float>& x) {
        float mse = mse_loss(x);
        if (train_std_ < 1e-8f || train_mean_ < 1e-8f)
            return std::clamp(mse * 2.f, 0.f, 1.f);
        return std::clamp(mse / (train_mean_ * 3.f), 0.f, 1.f);
    }

    // Record training stats for normalization
    void record_stats(const std::vector<std::vector<float>>& val_set) {
        std::vector<float> errors;
        for (const auto& x : val_set)
            errors.push_back(mse_loss(x));
        if (errors.empty()) return;
        double sum = std::accumulate(errors.begin(), errors.end(), 0.0);
        train_mean_ = static_cast<float>(sum / errors.size());
        double sq_sum = 0.0;
        for (float e : errors) sq_sum += (e - train_mean_) * (e - train_mean_);
        train_std_ = static_cast<float>(std::sqrt(sq_sum / errors.size()));
        if (train_std_ < 1e-8f) train_std_ = 0.01f;
    }

    size_t input_dim() const { return input_dim_; }

    bool save(const std::string& path) const {
        std::ofstream f(path, std::ios::binary);
        if (!f) return false;
        auto write = [&](const auto& v) {
            f.write(reinterpret_cast<const char*>(v.data()), v.size() * sizeof(float));
        };
        uint32_t dim = static_cast<uint32_t>(input_dim_);
        f.write(reinterpret_cast<const char*>(&dim), sizeof(dim));
        f.write(reinterpret_cast<const char*>(&train_mean_), sizeof(train_mean_));
        f.write(reinterpret_cast<const char*>(&train_std_), sizeof(train_std_));
        write(enc1_.w.data); write(enc1_.b.data);
        write(enc2_.w.data); write(enc2_.b.data);
        write(dec1_.w.data); write(dec1_.b.data);
        write(dec2_.w.data); write(dec2_.b.data);
        return f.good();
    }

    bool load(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        auto read = [&](auto& v) {
            f.read(reinterpret_cast<char*>(v.data()), v.size() * sizeof(float));
        };
        uint32_t dim = 0;
        f.read(reinterpret_cast<char*>(&dim), sizeof(dim));
        if (dim != input_dim_) return false;
        f.read(reinterpret_cast<char*>(&train_mean_), sizeof(train_mean_));
        f.read(reinterpret_cast<char*>(&train_std_), sizeof(train_std_));
        read(enc1_.w.data); read(enc1_.b.data);
        read(enc2_.w.data); read(enc2_.b.data);
        read(dec1_.w.data); read(dec1_.b.data);
        read(dec2_.w.data); read(dec2_.b.data);
        return f.good();
    }

private:
    std::minstd_rand rng_{42};
    Layer enc1_, enc2_, dec1_, dec2_;
    SGD opt_;
    size_t input_dim_;
    float train_mean_ = 0.f;
    float train_std_  = 0.01f;
};

} // namespace ids
