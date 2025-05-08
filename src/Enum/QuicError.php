<?php

namespace Tourze\Workerman\QUIC\Enum;

enum QuicError: int
{
    case NO_ERROR = 0x0;
    case INTERNAL_ERROR = 0x1;
    case CONNECTION_REFUSED = 0x2;
    case FLOW_CONTROL_ERROR = 0x3;
    case STREAM_LIMIT_ERROR = 0x4;
    case STREAM_STATE_ERROR = 0x5;
    case FINAL_SIZE_ERROR = 0x6;
    case FRAME_ENCODING_ERROR = 0x7;
    case TRANSPORT_PARAMETER_ERROR = 0x8;
    case CONNECTION_ID_LIMIT_ERROR = 0x9;
    case PROTOCOL_VIOLATION = 0xA;
    case INVALID_TOKEN = 0xB;
    case APPLICATION_ERROR = 0xC;
    case CRYPTO_BUFFER_EXCEEDED = 0xD;
    case KEY_UPDATE_ERROR = 0xE;
    case AEAD_LIMIT_REACHED = 0xF;
    case NO_VIABLE_PATH = 0x10;
} 