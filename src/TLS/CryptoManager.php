<?php

namespace Tourze\Workerman\QUIC\TLS;

class CryptoManager
{
    /**
     * 加密应用数据
     * @param string $data
     * @param int $packetNumber
     * @param string $key
     * @return string
     */
    public function encrypt(string $data, int $packetNumber, string $key): string
    {
        $nonce = $this->generateNonce($packetNumber);
        $aad = $this->generateAAD($packetNumber, strlen($data));

        $tag = '';
        $ciphertext = openssl_encrypt(
            $data,
            'aes-128-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad
        );

        return $ciphertext . $tag;
    }

    /**
     * 解密应用数据
     * @param string $data
     * @param int $packetNumber
     * @param string $key
     * @return string
     */
    public function decrypt(string $data, int $packetNumber, string $key): string
    {
        $nonce = $this->generateNonce($packetNumber);
        $tag = substr($data, -16);
        $ciphertext = substr($data, 0, -16);
        $aad = $this->generateAAD($packetNumber, strlen($ciphertext));

        return openssl_decrypt(
            $ciphertext,
            'aes-128-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad
        );
    }

    /**
     * 生成 Nonce
     * @param int $packetNumber
     * @return string
     */
    private function generateNonce(int $packetNumber): string
    {
        $iv = random_bytes(12);
        $pn = pack('J', $packetNumber);

        $result = '';
        for ($i = 0; $i < 12; $i++) {
            $result .= chr(ord($iv[$i]) ^ ord($pn[7 - ($i % 8)]));
        }

        return $result;
    }

    /**
     * 生成 AAD (Additional Authenticated Data)
     * @param int $packetNumber
     * @param int $length
     * @return string
     */
    private function generateAAD(int $packetNumber, int $length): string
    {
        return pack('J', $packetNumber) . pack('n', $length);
    }
}
