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

CREATE TABLE yubikeys (
    -- identities:
    serialnr INT NOT NULL,
    publicname VARCHAR(16) UNIQUE NOT NULL,

    -- timestamps:
    created VARCHAR(24) NOT NULL,

    -- the data:
    internalname VARCHAR(12) NOT NULL,
    aeskey VARCHAR(32) NOT NULL,
    lockcode VARCHAR(12) NOT NULL,

    -- key creator, typically pgp key id of key generator
    creator VARCHAR(8) NOT NULL,

    -- various flags:
    active BOOLEAN DEFAULT TRUE,
    hardware BOOLEAN DEFAULT TRUE,

    PRIMARY KEY (publicname)
);
