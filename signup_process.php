<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
include 'db_connect.php';

// POST 요청인지 확인
if ($_SERVER["REQUEST_METHOD"] != "POST") {
    echo "<script>alert('잘못된 접근입니다.'); window.location.href='signup.html';</script>";
    exit();
}

// 폼 데이터 받기
$email = $conn->real_escape_string($_POST['email']);
$userid = $conn->real_escape_string($_POST['userid']);
$password_input = $_POST['password'];

// 중복 체크
$check_duplicate_sql = "SELECT COUNT(*) AS count FROM user WHERE userid = '$userid' OR email = '$email'";
$duplicate_result = $conn->query($check_duplicate_sql);
$row = $duplicate_result->fetch_assoc();
$duplicate_count = $row['count'];

// 중복 체크 (Prepared Statement 사용 - 보안 강화)
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


if ($duplicate_count > 0) {
    echo "<script>alert('이미 사용 중인 이메일입니다.'); window.location.href='signup.html';</script>";
    $conn->close();
    exit();
}

// 비밀번호 해시화 & 삽입
$password_hashed = password_hash($password_input, PASSWORD_DEFAULT);
$insert_sql = "INSERT INTO user (email, userid, password) VALUES ('$email', '$userid', '$password_hashed')";

if ($conn->query($insert_sql) === TRUE) {
    echo "<script>alert('회원가입이 완료되었습니다!'); window.location.href='login.html';</script>";
} else {
    echo "<script>alert('회원가입 중 오류가 발생했습니다.'); window.location.href='signup.html';</script>";
}

$conn->close();
?>
