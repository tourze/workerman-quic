#!/usr/bin/env php
<?php

use App\Protocol\QUIC\QUICProtocol;
use Workerman\Connection\TcpConnection;
use Workerman\Worker;

require_once __DIR__ . '/vendor/autoload.php';

// 创建 QUIC 服务器
$quicServer = new Worker('quic://0.0.0.0:8443');
$quicServer->protocol = QUICProtocol::class;

// 设置进程数
$quicServer->count = 4;

// 当客户端连接时
$quicServer->onConnect = function(TcpConnection $connection) {
    echo "New QUIC connection\n";
};

// 当收到客户端数据时
$quicServer->onMessage = function(TcpConnection $connection, $data) {
    echo "Received data: " . $data . "\n";
    // 回复客户端
    $connection->send("Hello from QUIC server!");
};

// 当客户端断开时
$quicServer->onClose = function(TcpConnection $connection) {
    echo "QUIC connection closed\n";
};

// 创建 QUIC 客户端
$quicClient = new Worker();
$quicClient->onWorkerStart = function() {
    // 创建 QUIC 客户端连接
    $client = new \Workerman\Connection\AsyncTcpConnection('quic://127.0.0.1:8443');
    $client->protocol = QUICProtocol::class;

    // 当连接建立时发送数据
    $client->onConnect = function($connection) {
        echo "Connected to QUIC server\n";
        $connection->send("Hello from QUIC client!");
    };

    // 当收到服务器响应时
    $client->onMessage = function($connection, $data) {
        echo "Received from server: " . $data . "\n";
    };

    // 当连接关闭时
    $client->onClose = function($connection) {
        echo "Connection to QUIC server closed\n";
    };

    // 启动连接
    $client->connect();
};

// 运行所有 workers
Worker::runAll();
