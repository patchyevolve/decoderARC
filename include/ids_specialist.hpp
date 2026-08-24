#pragma once
#include "ids_types.hpp"
#include <string>
#include <vector>
#include <future>
#include <memory>

namespace ids {

struct IDSConfig; // Forward declaration

/**
 * @brief Result from a specialist's analysis.
 */
struct SpecialistResult {
    std::string attack_class;
    float       confidence = 0.0f;
    Decision    suggested_decision = Decision::Ignore;
    std::string details;
    bool        validated = false;
};

/**
 * @brief Interface for validating a specialist's decision.
 * Each specialist can have its own validation logic.
 */
class SpecialistValidator {
public:
    virtual ~SpecialistValidator() = default;
    virtual bool validate(const Event& ev, const SpecialistResult& res) = 0;
    virtual std::string validator_name() const = 0;
};

/**
 * @brief Enhanced Specialist interface supporting parallel execution and validation.
 */
class Specialist {
public:
    virtual ~Specialist() = default;

    virtual void initialize(const IDSConfig& cfg) = 0;
    
    // Analyze an event and return a result
    virtual SpecialistResult analyze(const Event& ev) = 0;
    
    virtual std::string attack_class() const = 0;
    
    // Each specialist can have a validator
    virtual void set_validator(std::unique_ptr<SpecialistValidator> validator) {
        validator_ = std::move(validator);
    }
    
    bool validate_result(const Event& ev, const SpecialistResult& res) {
        if (validator_) return validator_->validate(ev, res);
        return true; // Default to true if no validator
    }

protected:
    std::unique_ptr<SpecialistValidator> validator_;
};

/**
 * @brief A specialist that detects attacks based on MITRE patterns or Zero-day indicators.
 */
class ComplexThreatSpecialist : public Specialist {
public:
    virtual std::vector<std::string> mitre_techniques() const = 0;
};

} // namespace ids
