-- board_db 스키마
-- 게시판에서 쓰는 테이블은 posts 하나뿐입니다.
-- ORM 없이, 이 파일 내용을 그대로 mysql에 실행해서 테이블을 만듭니다.

CREATE DATABASE IF NOT EXISTS board_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; -- 한글이 깨지지 않게 utf8mb4로 지정했습니다.

USE board_db;

CREATE TABLE IF NOT EXISTS posts (
  id INT AUTO_INCREMENT PRIMARY KEY,          -- 글 번호, 자동으로 1씩 늘어남
  title VARCHAR(200) NOT NULL,                -- 제목
  author VARCHAR(50) NOT NULL DEFAULT '익명', -- 작성자, 안 적으면 익명으로 저장됨
  content TEXT NOT NULL,                      -- 본문. 길게 쓸 수도 있어서 TEXT로 잡음
  password_hash VARCHAR(255) NOT NULL,        -- 수정/삭제할 때 확인하는 비밀번호 (해시로 저장, 평문 저장 X)
  is_secret TINYINT(1) NOT NULL DEFAULT 0,    -- 비밀글 여부. 1이면 password_hash를 맞춰야만 내용이 보임
  views INT NOT NULL DEFAULT 0,               -- 조회수. 글 볼 때마다 1씩 늘어남
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,                            -- 작성일
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP  -- 수정일, 수정하면 자동으로 갱신됨
) ENGINE=InnoDB;

-- 이미 만들어져 있던 DB(컬럼 추가 전)에도 반영되도록, 컬럼이 없을 때만 추가합니다.
-- "ADD COLUMN IF NOT EXISTS" 문법은 MySQL 버전에 따라 지원 여부가 달라서, 대신
-- information_schema로 직접 확인한 다음 동적 SQL로 실행하는 방식을 썼습니다.
SET @add_is_secret = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'posts' AND COLUMN_NAME = 'is_secret') = 0,
    'ALTER TABLE posts ADD COLUMN is_secret TINYINT(1) NOT NULL DEFAULT 0 AFTER password_hash',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_is_secret;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 첨부파일 테이블. 글 하나에 여러 파일을 붙일 수 있어서 posts와 별도 테이블로 분리했습니다.
-- 실제 파일은 디스크의 uploads 폴더에 저장하고, 여기에는 그 파일을 찾기 위한 정보만 담습니다.
CREATE TABLE IF NOT EXISTS attachments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  post_id INT NOT NULL,
  original_filename VARCHAR(255) NOT NULL,   -- 사용자가 올린 원래 파일명. 다운로드할 때 이 이름으로 내려줌
  stored_filename VARCHAR(255) NOT NULL UNIQUE, -- 실제 디스크에 저장된 파일명 (UUID). 원래 파일명을 그대로 안 쓰는 이유는 app.py 주석 참고
  content_type VARCHAR(100) NOT NULL,        -- 파일 내용을 직접 검사해서 서버가 판단한 MIME 타입 (클라이언트가 보낸 값 아님)
  size_bytes INT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 회원 테이블. 게시글의 작성자명/비밀번호와는 완전히 별개로, 로그인용 계정을 담습니다.
-- 아이디/비밀번호뿐 아니라 이름/학교까지 받아서 "내 프로필" 페이지에 보여줍니다.
-- is_admin은 회원가입으로는 절대 켜지지 않고(기본값 0), 관리자로 지정할 사람만
-- DB에서 직접 UPDATE users SET is_admin = 1 WHERE username = '...' 로 바꿔줍니다.
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,     -- 로그인용 아이디
  password_hash VARCHAR(255) NOT NULL,      -- 해시로 저장, 평문 저장 X
  name VARCHAR(50) NOT NULL,                -- 이름
  school VARCHAR(100) NOT NULL,             -- 학교
  birth_date DATE,                          -- 생년월일
  gender VARCHAR(10),                       -- 성별 ("남성"/"여성"/NULL=선택 안 함)
  nationality VARCHAR(50),                  -- 국적
  profile_image VARCHAR(255),               -- 프로필 이미지 저장 파일명(UUID). 안 올렸으면 NULL
  is_admin TINYINT(1) NOT NULL DEFAULT 0,   -- 회원목록처럼 관리자 전용 기능을 볼 수 있는지
  is_profile_public TINYINT(1) NOT NULL DEFAULT 1, -- 0이면 본인/관리자 말고는 프로필 상세를 못 봄
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- users 테이블이 is_admin 추가 전에 이미 만들어져 있었을 수도 있으니, 이것도 posts.is_secret과
-- 같은 방식으로 컬럼이 없을 때만 추가합니다.
SET @add_users_is_admin = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'is_admin') = 0,
    'ALTER TABLE users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0 AFTER profile_image',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_users_is_admin;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- users 테이블이 아래 컬럼들 추가 전에 이미 만들어져 있었을 수도 있으니, 이것도 마찬가지로
-- 컬럼이 없을 때만 하나씩 추가합니다.
SET @add_users_birth_date = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'birth_date') = 0,
    'ALTER TABLE users ADD COLUMN birth_date DATE AFTER school',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_users_birth_date;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @add_users_gender = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'gender') = 0,
    'ALTER TABLE users ADD COLUMN gender VARCHAR(10) AFTER birth_date',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_users_gender;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @add_users_nationality = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'nationality') = 0,
    'ALTER TABLE users ADD COLUMN nationality VARCHAR(50) AFTER gender',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_users_nationality;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @add_users_is_profile_public = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'is_profile_public') = 0,
    'ALTER TABLE users ADD COLUMN is_profile_public TINYINT(1) NOT NULL DEFAULT 1 AFTER is_admin',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_users_is_profile_public;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 게시글을 로그인한 회원이 썼다면, 그 회원 계정과 연결해서 프로필을 보여주기 위한 컬럼입니다.
-- 비회원이 쓴 글은 지금까지처럼 user_id가 NULL이고 작성자명/비밀번호만으로 관리됩니다.
-- 회원 계정이 나중에 삭제되더라도 글 자체는 남아있어야 하므로 ON DELETE SET NULL로 뒀습니다.
SET @add_posts_user_id = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'posts' AND COLUMN_NAME = 'user_id') = 0,
    'ALTER TABLE posts ADD COLUMN user_id INT NULL AFTER author',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_posts_user_id;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @add_posts_user_id_fk = (
  SELECT IF(
    (SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'posts' AND CONSTRAINT_NAME = 'posts_user_id_fk') = 0,
    'ALTER TABLE posts ADD CONSTRAINT posts_user_id_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT 1'
  )
);
PREPARE stmt FROM @add_posts_user_id_fk;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
