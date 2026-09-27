module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "OleAut32.lib")
export module Hook:Ole32;

import "sys_defs.h";
import std;
import :Core;
import GlobalData;

#include "WmiResult.inl"
