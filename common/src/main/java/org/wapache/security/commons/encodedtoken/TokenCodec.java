/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wapache.security.commons.encodedtoken;

import org.apache.commons.codec.binary.Base64;

import java.nio.charset.Charset;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;

public abstract class TokenCodec {

    /**
     * The Base64 JSON string default separator.
     * JWT Token的3段式结构.
     */
    public static Pattern base64urlTokenPattern = Pattern.compile("([a-zA-Z0-9-​_=]+)\\.([a-zA-Z0-9-_​=]+)\\.([a-zA-Z0-9-_=]+)");

//    public static String base64Decode(String base64encoded) {
//        return new String(base64DecodeToByte(base64encoded), UTF_8);
//    }
//    public static String base64Encode(String input) {
//        return new String(base64EncodeToByte(input.getBytes(UTF_8)), UTF_8);
//    }
//    public static String base64Encode(byte[] input) {
//        return new String(base64EncodeToByte(input), UTF_8);
//    }
//
//    public static byte[] base64DecodeToByte(String base64encoded) {
//        return java.util.Base64.getDecoder().decode(base64encoded);
//    }
//    public static byte[] base64EncodeToByte(byte [] input) {
//        return java.util.Base64.getEncoder().encode(input);
//    }

    /**
     * Empty Line separator for rfc 2045 section 6.8
     * {@see org.apache.commons.codec.binary.Base64}
     */
    private static final byte[] LINE_SEPARATOR = {};

    public static final String base64Decode(String base64encoded) {
        return new String(new Base64(-1, LINE_SEPARATOR, true).decode(base64encoded), UTF_8);
    }

    public static final byte[] base64DecodeToByte(String base64encoded) {
        return new Base64(-1, LINE_SEPARATOR, true).decode(base64encoded);
    }

    public static final String base64Encode(String input) {
        return new String(new Base64(-1, LINE_SEPARATOR, true).encode(input.getBytes(UTF_8)), UTF_8);
    }

    public static final String base64Encode(byte [] input) {
        return new String(new Base64(-1, LINE_SEPARATOR, true).encode(input));
    }
}
