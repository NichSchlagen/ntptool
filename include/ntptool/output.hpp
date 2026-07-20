#pragma once

// -----------------------------------------------------------------------------
// Terminal colour handling and shared result formatting helpers.
// -----------------------------------------------------------------------------

#include <ostream>
#include <string>

#include "ntptool/ntp_client.hpp"

namespace ntptool {

// ANSI colouring gated on a runtime flag (auto-disabled for non-TTY output).
class Colorizer {
public:
    bool enabled = false;

    std::string paint(const char* code, const std::string& s) const;
    std::string bold(const std::string& s) const { return paint("1", s); }
    std::string dim(const std::string& s) const { return paint("2", s); }
    std::string red(const std::string& s) const { return paint("31", s); }
    std::string green(const std::string& s) const { return paint("32", s); }
    std::string yellow(const std::string& s) const { return paint("33", s); }
    std::string blue(const std::string& s) const { return paint("34", s); }
    std::string magenta(const std::string& s) const { return paint("35", s); }
    std::string cyan(const std::string& s) const { return paint("36", s); }
};

// Colour an offset by magnitude: green < 10 ms, yellow < 100 ms, else red.
std::string colorize_offset(const Colorizer& c, double offset_seconds);

// A one-word quality rating for an absolute offset.
const char* offset_quality(double offset_seconds);

// Pretty multi-line report for a single measurement.
void print_query_report(std::ostream& os, const std::string& host,
                        const QueryResult& r, const Colorizer& c, int verbose);

// Serialise a single measurement as a JSON object (with the given indent).
std::string query_result_to_json(const std::string& host, const QueryResult& r,
                                  int indent);

// CSV header and one CSV row for a measurement.
std::string query_csv_header();
std::string query_csv_row(const std::string& host, const QueryResult& r);

}  // namespace ntptool
