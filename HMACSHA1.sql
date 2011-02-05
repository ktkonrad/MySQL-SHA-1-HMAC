/*
Author: Kyle Konrad
Date: 1/19/2011

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

DROP FUNCTION IF EXISTS HMACSHA1;

-- here email is the message generate a HMAC for
DELIMITER //
CREATE FUNCTION HMACSHA1(secret_key VARCHAR(36), email VARCHAR(128)) RETURNS CHAR(40) DETERMINISTIC
BEGIN
DECLARE ipad,opad BINARY(64);
DECLARE hexkey CHAR(128);
DECLARE hmac CHAR(40);

SET hexkey = RPAD(HEX(secret_key),128,"0");


/* process in 64-bit blocks to avoid overflow when converting to decimal*/
SET ipad = UNHEX(CONCAT(
LPAD(CONV(CONV( MID(hexkey,1  ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,17 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,33 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,49 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,65 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,81 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,97 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,113,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0")
));

SET opad = UNHEX(CONCAT(
LPAD(CONV(CONV( MID(hexkey,1  ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,17 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,33 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,49 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,65 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,81 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,97 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,113,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0")
));

SET hmac = SHA1(CONCAT(opad,UNHEX(SHA1(CONCAT(ipad,email)))));

RETURN hmac;

END //
DELIMITER ;
