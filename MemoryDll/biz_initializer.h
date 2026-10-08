#pragma once
#include "sys_defs.h"
// `params` must already be validated: rootPathCount wchar_t and launchConfigBytes bytes follow rootPath.
void biz_initialize(const DetourInjectParams* params);
