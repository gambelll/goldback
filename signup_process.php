<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
include 'db_connect.php';

if ($_SERVER["REQUEST_METHOD"] != "POST") {
    echo "<script>alert('잘못된 접근입니다.'); window.location.href='signup.html';</script>";
    exit();
}

$email = $conn->real_escape_string($_POST['email']);
$userid = $conn->real_escape_string($_POST['userid']);
$password_input = $_POST['password'];

$check_stmt = $conn->prepare("SELECT COUNT(*) FROM user WHERE userid = ? OR email = ?");
$check_stmt->bind_param("ss", $userid, $email);
$check_stmt->execute();
$check_stmt->bind_result($duplicate_count);
$check_stmt->fetch();
$check_stmt->close();

if ($duplicate_count > 0) {
    echo "<script>alert('이미 사용 중인 이메일 또는 아이디입니다.'); window.location.href='signup.html';</script>";
    $conn->close();
    exit();
}

$password_hashed = password_hash($password_input, PASSWORD_DEFAULT);

$insert_stmt = $conn->prepare("INSERT INTO user (email, userid, password) VALUES (?, ?, ?)");
$insert_stmt->bind_param("sss", $email, $userid, $password_hashed);

if ($insert_stmt->execute()) {
    echo "<script>alert('회원가입이 완료되었습니다!'); window.location.href='login.html';</script>";
} else {
    echo "<script>alert('회원가입 중 오류가 발생했습니다.'); window.location.href='signup.html';</script>";
}

$insert_stmt->close();
$conn->close();
?>
