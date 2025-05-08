<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\ECNState;

class PacketManager
{
    /**
     * 已接收的数据包
     * @var array
     */
    private $_receivedPackets = [];

    /**
     * 未确认的数据包
     * @var array
     */
    private $_unackedPackets = [];

    /**
     * ACK 块
     * @var array
     */
    private $_ackRanges = [];

    /**
     * ECN 计数
     * @var array
     */
    private $_ecnCounts = [
        'ect0' => 0,
        'ect1' => 0,
        'ce' => 0
    ];

    /**
     * ECN 验证状态
     * @var ECNState
     */
    private ECNState $_ecnState = ECNState::UNKNOWN;

    /**
     * 最大接收包号
     * @var int
     */
    private $_largestReceivedPacketNumber = -1;

    /**
     * 最后发送 ACK 的时间
     * @var float
     */
    private $_lastAckTime = 0;

    /**
     * ACK 延迟
     * @var float
     */
    private $_ackDelay = 0.025; // 25ms

    /**
     * 处理接收到的数据包
     * @param Packet $packet
     * @param bool $ecnSet
     */
    public function processReceivedPacket(Packet $packet, bool $ecnSet = false): void
    {
        $packetNumber = $packet->getPacketNumber();

        // 更新最大接收包号
        if ($packetNumber > $this->_largestReceivedPacketNumber) {
            $this->_largestReceivedPacketNumber = $packetNumber;
        }

        // 记录接收时间
        $this->_receivedPackets[$packetNumber] = [
            'time' => microtime(true),
            'processed' => false
        ];

        // 更新 ECN 计数
        if ($ecnSet) {
            $this->_ecnCounts['ce']++;
        }

        // 更新 ACK 块
        $this->updateAckRanges($packetNumber);
    }

    /**
     * 更新 ACK 块
     * @param int $packetNumber
     */
    private function updateAckRanges(int $packetNumber): void
    {
        // 如果是第一个包
        if (empty($this->_ackRanges)) {
            $this->_ackRanges[] = [
                'start' => $packetNumber,
                'end' => $packetNumber
            ];
            return;
        }

        // 查找合适的位置插入
        foreach ($this->_ackRanges as $i => $range) {
            // 如果包号在当前块中
            if ($packetNumber >= $range['start'] && $packetNumber <= $range['end']) {
                return;
            }

            // 如果包号可以扩展当前块
            if ($packetNumber == $range['start'] - 1) {
                $this->_ackRanges[$i]['start'] = $packetNumber;
                // 尝试合并相邻块
                if ($i > 0 && $this->_ackRanges[$i - 1]['end'] == $packetNumber - 1) {
                    $this->_ackRanges[$i]['start'] = $this->_ackRanges[$i - 1]['start'];
                    unset($this->_ackRanges[$i - 1]);
                    $this->_ackRanges = array_values($this->_ackRanges);
                }
                return;
            }

            if ($packetNumber == $range['end'] + 1) {
                $this->_ackRanges[$i]['end'] = $packetNumber;
                // 尝试合并相邻块
                if (isset($this->_ackRanges[$i + 1]) && 
                    $this->_ackRanges[$i + 1]['start'] == $packetNumber + 1) {
                    $this->_ackRanges[$i]['end'] = $this->_ackRanges[$i + 1]['end'];
                    unset($this->_ackRanges[$i + 1]);
                    $this->_ackRanges = array_values($this->_ackRanges);
                }
                return;
            }

            // 如果需要插入新块
            if ($packetNumber > $range['end']) {
                array_splice($this->_ackRanges, $i, 0, [[
                    'start' => $packetNumber,
                    'end' => $packetNumber
                ]]);
                return;
            }
        }

        // 如果是最小的包号,添加到末尾
        $this->_ackRanges[] = [
            'start' => $packetNumber,
            'end' => $packetNumber
        ];
    }

    /**
     * 生成 ACK 帧
     * @return string|null
     */
    public function generateAckFrame(): ?string
    {
        if (empty($this->_ackRanges)) {
            return null;
        }

        $now = microtime(true);
        
        // 检查是否需要发送 ACK
        if ($now - $this->_lastAckTime < $this->_ackDelay) {
            return null;
        }

        // 计算延迟
        $ackDelay = (int)(($now - $this->_receivedPackets[$this->_largestReceivedPacketNumber]['time']) * 1000000);

        // 构造 ACK 帧
        $frameData = pack('J', $this->_largestReceivedPacketNumber); // 最大包号
        $frameData .= pack('J', $ackDelay); // 延迟(微秒)
        $frameData .= pack('n', count($this->_ackRanges)); // ACK 块数量

        // 添加 ACK 块
        foreach ($this->_ackRanges as $range) {
            $gap = $this->_largestReceivedPacketNumber - $range['end'];
            $ackBlock = $range['end'] - $range['start'];
            $frameData .= pack('JJ', $gap, $ackBlock);
        }

        // 如果启用了 ECN
        if ($this->_ecnState === ECNState::TESTING || $this->_ecnState === ECNState::UNKNOWN) {
            $frameData .= pack('JJJ',
                $this->_ecnCounts['ect0'],
                $this->_ecnCounts['ect1'],
                $this->_ecnCounts['ce']
            );
        }

        $this->_lastAckTime = $now;

        return $frameData;
    }

    /**
     * 处理 ACK 帧
     * @param string $frameData
     */
    public function handleAckFrame(string $frameData): void
    {
        $offset = 0;

        // 解析最大包号
        $largestAcked = unpack('J', substr($frameData, $offset, 8))[1];
        $offset += 8;

        // 解析延迟
        $ackDelay = unpack('J', substr($frameData, $offset, 8))[1];
        $offset += 8;

        // 解析 ACK 块数量
        $blockCount = unpack('n', substr($frameData, $offset, 2))[1];
        $offset += 2;

        // 处理 ACK 块
        $currentPacket = $largestAcked;
        for ($i = 0; $i < $blockCount; $i++) {
            $gap = unpack('J', substr($frameData, $offset, 8))[1];
            $offset += 8;
            $blockLength = unpack('J', substr($frameData, $offset, 8))[1];
            $offset += 8;

            // 标记已确认的包
            for ($pn = $currentPacket; $pn >= $currentPacket - $blockLength; $pn--) {
                if (isset($this->_unackedPackets[$pn])) {
                    unset($this->_unackedPackets[$pn]);
                }
            }

            $currentPacket -= $blockLength + $gap;
        }

        // 如果还有 ECN 计数
        if ($offset < strlen($frameData)) {
            $ect0 = unpack('J', substr($frameData, $offset, 8))[1];
            $offset += 8;
            $ect1 = unpack('J', substr($frameData, $offset, 8))[1];
            $offset += 8;
            $ce = unpack('J', substr($frameData, $offset, 8))[1];

            $this->validateEcnCounts($ect0, $ect1, $ce);
        }
    }

    /**
     * 验证 ECN 计数
     * @param int $ect0
     * @param int $ect1
     * @param int $ce
     */
    private function validateEcnCounts(int $ect0, int $ect1, int $ce): void
    {
        if ($this->_ecnState === ECNState::TESTING) {
            // 检查计数是否合理
            if ($ect0 + $ect1 + $ce > count($this->_unackedPackets)) {
                $this->_ecnState = ECNState::FAILED;
                return;
            }

            // 如果所有包都被标记为 CE
            if ($ce === count($this->_unackedPackets)) {
                $this->_ecnState = ECNState::FAILED;
                return;
            }

            $this->_ecnState = ECNState::UNKNOWN;
        } elseif ($this->_ecnState === ECNState::UNKNOWN) {
            // 如果有包被确认且计数合理
            if ($ect0 + $ect1 > 0 && $ect0 + $ect1 + $ce <= count($this->_unackedPackets)) {
                $this->_ecnState = ECNState::CAPABLE;
            }
        }
    }

    /**
     * 获取 ECN 状态
     * @return ECNState
     */
    public function getEcnState(): ECNState
    {
        return $this->_ecnState;
    }

    /**
     * 设置 ECN 状态
     * @param ECNState $state
     */
    public function setEcnState(ECNState $state): void
    {
        $this->_ecnState = $state;
    }

    /**
     * 重置 ECN 计数
     */
    public function resetEcnCounts(): void
    {
        $this->_ecnCounts = [
            'ect0' => 0,
            'ect1' => 0,
            'ce' => 0
        ];
    }
} 