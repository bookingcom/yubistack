--  Copyright 2020 Booking.com
--
--  Licensed under the Apache License, Version 2.0 (the "License");
--  you may not use this file except in compliance with the License.
--  You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and

CREATE TABLE user_yubikeys (
    user_id INT NOT NULL,
    yubikey_id INT NOT NULL
);

CREATE TABLE users (
    id INT NOT NULL UNIQUE,
    name VARCHAR(32) NOT NULL,
    auth VARCHAR(128) DEFAULT NULL,
    attribute_association_id INT DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE yubikeys (
    id INT NOT NULL UNIQUE,
    prefix VARCHAR(32) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    attribute_association_id INT DEFAULT NULL,
    PRIMARY KEY (id)
);