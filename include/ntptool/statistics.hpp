#pragma once

// -----------------------------------------------------------------------------
// A simple numeric series with the summary statistics relevant to NTP
// measurements (min/max/mean/median/stddev and RMS jitter).
// -----------------------------------------------------------------------------

#include <cstddef>
#include <vector>

namespace ntptool {

struct StatSummary {
    size_t n = 0;
    double min = 0.0;
    double max = 0.0;
    double mean = 0.0;
    double median = 0.0;
    double stddev = 0.0;   // sample standard deviation (n-1)
    double jitter = 0.0;   // RMS of successive differences (RFC 5905 style)
};

class Series {
public:
    void add(double v) { data_.push_back(v); }
    void reserve(size_t n) { data_.reserve(n); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    void clear() { data_.clear(); }

    double last() const { return data_.empty() ? 0.0 : data_.back(); }
    const std::vector<double>& data() const { return data_; }

    StatSummary summary() const;

private:
    std::vector<double> data_;
};

}  // namespace ntptool
