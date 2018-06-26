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

CREATE TABLE clients (
    id INT NOT NULL UNIQUE,
    active BOOLEAN DEFAULT TRUE,
    created INT NOT NULL,
    secret VARCHAR(60) NOT NULL DEFAULT '',
    email VARCHAR(255),
    notes VARCHAR(100) DEFAULT '',
    otp VARCHAR(100) DEFAULT '',
    PRIMARY KEY (ID)
);

CREATE TABLE yubikeys (
    active BOOLEAN DEFAULT TRUE,
    created INT NOT NULL,
    modified INT NOT NULL,
    yk_publicname VARCHAR(16) UNIQUE NOT NULL,
    yk_counter INT NOT NULL,
    yk_use INT NOT NULL,
    yk_low INT NOT NULL,
    yk_high INT NOT NULL,
    nonce VARCHAR(40) DEFAULT '',
    notes VARCHAR(100) DEFAULT '',
    PRIMARY KEY (yk_publicname)
);
