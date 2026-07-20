#include "ntptool/statistics.hpp"

#include <algorithm>
#include <cmath>

namespace ntptool {

StatSummary Series::summary() const {
    StatSummary s;
    s.n = data_.size();
    if (data_.empty()) return s;

    s.min = data_.front();
    s.max = data_.front();
    double sum = 0.0;
    for (double v : data_) {
        s.min = std::min(s.min, v);
        s.max = std::max(s.max, v);
        sum += v;
    }
    s.mean = sum / static_cast<double>(s.n);

    // Sample standard deviation.
    if (s.n > 1) {
        double acc = 0.0;
        for (double v : data_) {
            double d = v - s.mean;
            acc += d * d;
        }
        s.stddev = std::sqrt(acc / static_cast<double>(s.n - 1));
    }

    // Median (on a sorted copy).
    std::vector<double> sorted = data_;
    std::sort(sorted.begin(), sorted.end());
    size_t mid = s.n / 2;
    s.median = (s.n % 2 == 0) ? (sorted[mid - 1] + sorted[mid]) / 2.0
                              : sorted[mid];

    // RMS jitter: root-mean-square of successive differences.
    if (s.n > 1) {
        double acc = 0.0;
        for (size_t i = 1; i < s.n; ++i) {
            double d = data_[i] - data_[i - 1];
            acc += d * d;
        }
        s.jitter = std::sqrt(acc / static_cast<double>(s.n - 1));
    }

    return s;
}

}  // namespace ntptool
