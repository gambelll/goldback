<?php
header('Content-Type: application/json; charset=utf-8');
session_start();

error_reporting(E_ALL);
ini_set('display_errors', 1);

$host = "sql311.infinityfree.com";
$user = "if0_39128377";
$password = "Rpaqpf1225"; // 변수명이 $pass → $password 로 수정
$dbname = "if0_39128377_user_db";

$conn = new mysqli($host, $user, $password, $dbname);
if ($conn->connect_error) {
    echo json_encode(['status' => 'error', 'message' => 'DB 연결 실패: ' . $conn->connect_error]);
    exit;
}

$userid = $_POST['userid'] ?? '';
$password_input = $_POST['password'] ?? '';

if (!$userid || !$password_input) {
    echo json_encode(['status' => 'error', 'message' => '아이디와 비밀번호를 입력하세요']);
    exit;
}

$sql = "SELECT * FROM user WHERE userid = ?";
$stmt = $conn->prepare($sql);
if ($stmt === false) {
    echo json_encode(['status' => 'error', 'message' => 'SQL 준비 실패: ' . $conn->error]);
    exit;
}
$stmt->bind_param('s', $userid);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    if (password_verify($password_input, $row['password'])) {
        $_SESSION['userid'] = $row['userid'];
        echo json_encode(['status' => 'success', 'message' => '로그인 성공']);
    } else {
        echo json_encode(['status' => 'error', 'message' => '비밀번호가 틀렸습니다']);
    }
} else {
    echo json_encode(['status' => 'error', 'message' => '아이디가 존재하지 않습니다']);
}

$stmt->close();
$conn->close();
?>
