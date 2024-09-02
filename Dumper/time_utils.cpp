#include "time_utils.h"
#include <iomanip>
#include <sstream>

std::string tm_to_readable_time(std::tm ctx) {
    std::ostringstream oss;
    oss << std::put_time(&ctx, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}
