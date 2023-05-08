CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    settings VARCHAR(1000) NOT NULL DEFAULT ''
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS permissions (
    user_id INT NOT NULL,
    type VARCHAR(8) NOT NULL,
    type_id INT NOT NULL,
    UNIQUE KEY `id_user_type_type_id` (`user_id`, `type`, `type_id`)
) ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS projects (
    project_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    owner_id INT NOT NULL,
    settings VARCHAR(1000) NOT NULL DEFAULT ''
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    project_id INT NOT NULL,
    owner_id INT NOT NULL,
    settings VARCHAR(1000) NOT NULL DEFAULT '',
    UNIQUE KEY `id_name_project` (`name`, `project_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS classifications (
    classification_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(8) NOT NULL,
    data TEXT NOT NULL,
    project_id INT NOT NULL,
    owner_id INT NOT NULL,
    settings VARCHAR(1000) NOT NULL DEFAULT '',
    UNIQUE KEY `id_name_project` (`name`, `project_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS categories_classifications (
    category_id INT NOT NULL,
    classification_id INT NOT NULL,
    UNIQUE KEY `id_category_classification` (`category_id`, `classification_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS labels (
    label_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    project_id INT NOT NULL,
    owner_id INT NOT NULL,
    UNIQUE KEY `id_name_project` (`name`, `project_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS images (
    image_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    uri VARCHAR(1000) NOT NULL,
    type VARCHAR(1) NOT NULL,
    resolution VARCHAR(255) NOT NULL,
    project_id INT NOT NULL,
    owner_id INT NOT NULL,
    UNIQUE KEY `id_name_project` (`name`, `project_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS annotations (
    annotation_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(1) NOT NULL,
    shared VARCHAR(255) NOT NULL,
    image_id INT NOT NULL,
    project_id INT NOT NULL,
    category_id INT NOT NULL,
    owner_id INT NOT NULL,
    UNIQUE KEY `id_name_category` (`name`, `category_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS annotations_labels (
    annotation_id INT NOT NULL,
    label_id INT NOT NULL,
    UNIQUE KEY `id_annotation_label` (`annotation_id`, `label_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS layers (
    layer_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    data TEXT NOT NULL,
    image_id INT NOT NULL,
    sequence INT NOT NULL,
    parent_id INT NOT NULL,
    annotation_id INT NOT NULL,
    owner_id INT NOT NULL,
    UNIQUE KEY `id_name_annotation` (`name`, `annotation_id`)
)  ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS comments (
    comment_id INT AUTO_INCREMENT PRIMARY KEY,
    content TEXT NOT NULL,
    sequence INT NOT NULL,
    layer_id INT NOT NULL,
    owner_id INT NOT NULL
)  ENGINE=INNODB;

INSERT INTO users (user_id, username, name, password, email, settings) VALUES (1, 'sysadm', 'System administrator', '2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041', 'sysadm@yourdomain.com', '');
INSERT INTO permissions (user_id, type, type_id) values (1, 'sysadm', 1);
INSERT INTO permissions (user_id, type, type_id) values (1, 'proadm', 1);
