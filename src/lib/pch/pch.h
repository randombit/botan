/* IWYU pragma: begin_exports */

#include <algorithm>
#include <array>
#include <bit>
/*
* Note: <chrono> is intentionally omitted here, as even instantiating
* the templates in it from the PCH is so expensive that it is overall
* faster to not precompile it and accept the cost in the small number of
* files which continue to use <chrono>
*/
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <iosfwd>
#include <iostream>
#include <limits>
#include <locale>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

/* IWYU pragma: end_exports */
