#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "string.h"
#include <cstring>
#include <chrono>
#include <stdexcept>
#include <vector>
#include <map>
#include <math.h>
#include <algorithm>
#ifndef WIN32
#include <pthread.h>
#endif

// add openssl
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>// NID_secp256k1
#include <openssl/bn.h>
//

// secp256k1:
const unsigned int PRIVATE_KEY_SIZE = 279;
const unsigned int PUBLIC_KEY_SIZE  = 65;
//const unsigned int SIGNATURE_SIZE   = 72;

void SleepMillis(uint32_t millis) {

#ifdef WIN32
	Sleep(millis);
#else
	usleep(millis * 1000);
#endif

}
