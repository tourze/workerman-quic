<?php

namespace Tourze\Workerman\QUIC\Enum;

enum ECNState: string
{
    case TESTING = 'testing';
    case UNKNOWN = 'unknown';
    case CAPABLE = 'capable';
    case FAILED = 'failed';
}
