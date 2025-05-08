<?php

namespace Tourze\Workerman\QUIC\Enum;

enum PathState: string
{
    case PROBING = 'probing';
    case VALIDATING = 'validating';
    case VALIDATED = 'validated';
    case ACTIVE = 'active';
} 