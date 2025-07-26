#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <cstdlib>
#include <stdexcept>
#include <system_error>
#include <span>
#include <vector>
#include <string>
#include <algorithm>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>
#include <wil/filesystem.h>
