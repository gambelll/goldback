<?php
session_start();
session_unset();
session_destroy();
header("Location: index.html");  // 로그아웃 후 메인 페이지로 이동
exit;
?>
