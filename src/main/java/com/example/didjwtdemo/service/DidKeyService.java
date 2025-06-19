package com.example.didjwtdemo.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.security.*;
import java.util.Base64;

@Service
public class DidKeyService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        return kpg.generateKeyPair();
    }

    public String getDidFromPublicKey(PublicKey publicKey) {
        // did:key: base58 encoding with multicodec prefix (符合 DID Key 規範)
        byte[] pub = publicKey.getEncoded();
        
        // 加入 multicodec prefix: 0xD1, 0xD6, 0x03 (Ed25519)
        byte[] prefixedPub = new byte[pub.length + 3];
        prefixedPub[0] = (byte) 0xD1;
        prefixedPub[1] = (byte) 0xD6;
        prefixedPub[2] = (byte) 0x03;
        System.arraycopy(pub, 0, prefixedPub, 3, pub.length);
        
        String base58 = encodeBase58(prefixedPub);
        return "did:key:z" + base58;
    }

    public String sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("Ed25519", "BC");
        sig.initSign(privateKey);
        sig.update(data);
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("Ed25519", "BC");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    public String parseJwtPayload(String jwt) {
        // JWT 格式: header.payload.signature (Base64Url)
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) return null;
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        return payloadJson;
    }

    public String createJwt(String payload, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // header: {"alg":"EdDSA","typ":"JWT","did":"..."}
        String did = getDidFromPublicKey(publicKey);
        String headerJson = String.format("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"did\":\"%s\"}", did);
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes());
        String payloadBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
        String signingInput = header + "." + payloadBase64;
        String signature = sign(signingInput.getBytes(), privateKey);
        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getDecoder().decode(signature));
        return header + "." + payloadBase64 + "." + signatureBase64;
    }

    public String parseJwtHeader(String jwt) {
        // JWT 格式: header.payload.signature (Base64Url)
        String[] parts = jwt.split("\\.");
        if (parts.length < 1) return null;
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        return headerJson;
    }

    /**
     * 根據 did:key 取得 PublicKey
     * 支援標準 did:key:z{base58} 格式，包含 multicodec prefix
     */
    public PublicKey getPublicKeyFromDid(String didKey) throws Exception {
        if (didKey == null || !didKey.startsWith("did:key:z")) {
            throw new IllegalArgumentException("Invalid did:key format");
        }
        String base58 = didKey.substring("did:key:z".length());
        byte[] prefixedBytes = decodeBase58(base58);
        
        // 檢查 multicodec prefix: 0xD1, 0xD6, 0x03
        if (prefixedBytes.length < 3 || 
            prefixedBytes[0] != (byte) 0xD1 || 
            prefixedBytes[1] != (byte) 0xD6 || 
            prefixedBytes[2] != (byte) 0x03) {
            throw new IllegalArgumentException("Invalid multicodec prefix for Ed25519");
        }
        
        // 移除 prefix，只取公鑰部分
        byte[] pubBytes = new byte[prefixedBytes.length - 3];
        System.arraycopy(prefixedBytes, 3, pubBytes, 0, pubBytes.length);
        
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
        return kf.generatePublic(spec);
    }

    /**
     * Base58 編碼
     */
    private String encodeBase58(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        
        // Convert to base-256 digits
        int[] digits = new int[input.length];
        for (int i = 0; i < input.length; i++) {
            digits[i] = input[i] & 0xFF;
        }
        
        // Convert to base-58
        StringBuilder result = new StringBuilder();
        int[] base58Digits = new int[input.length * 2]; // Worst case scenario
        int base58DigitsLength = 0;
        
        for (int i = 0; i < digits.length; i++) {
            int carry = digits[i];
            for (int j = 0; j < base58DigitsLength; j++) {
                carry += base58Digits[j] * 256;
                base58Digits[j] = carry % 58;
                carry /= 58;
            }
            while (carry > 0) {
                base58Digits[base58DigitsLength++] = carry % 58;
                carry /= 58;
            }
        }
        
        // Convert to string
        for (int i = base58DigitsLength - 1; i >= 0; i--) {
            result.append(BASE58_ALPHABET.charAt(base58Digits[i]));
        }
        
        // Add leading zeros
        for (int i = 0; i < input.length && input[i] == 0; i++) {
            result.insert(0, '1');
        }
        
        return result.toString();
    }

    /**
     * Base58 解碼
     */
    private byte[] decodeBase58(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }
        
        // Convert from base-58 to base-256
        int[] digits = new int[input.length()];
        for (int i = 0; i < input.length(); i++) {
            int c = input.charAt(i);
            int digit = BASE58_ALPHABET.indexOf(c);
            if (digit == -1) {
                throw new IllegalArgumentException("Invalid Base58 character: " + c);
            }
            digits[i] = digit;
        }
        
        // Convert to base-256
        int[] base256Digits = new int[input.length()];
        int base256DigitsLength = 0;
        
        for (int i = 0; i < digits.length; i++) {
            int carry = digits[i];
            for (int j = 0; j < base256DigitsLength; j++) {
                carry += base256Digits[j] * 58;
                base256Digits[j] = carry % 256;
                carry /= 256;
            }
            while (carry > 0) {
                base256Digits[base256DigitsLength++] = carry % 256;
                carry /= 256;
            }
        }
        
        // Convert to bytes
        byte[] result = new byte[base256DigitsLength];
        for (int i = 0; i < base256DigitsLength; i++) {
            result[i] = (byte) base256Digits[base256DigitsLength - 1 - i];
        }
        
        // Add leading zeros
        int leadingZeros = 0;
        for (int i = 0; i < input.length() && input.charAt(i) == '1'; i++) {
            leadingZeros++;
        }
        
        if (leadingZeros > 0) {
            byte[] resultWithZeros = new byte[result.length + leadingZeros];
            System.arraycopy(result, 0, resultWithZeros, leadingZeros, result.length);
            return resultWithZeros;
        }
        
        return result;
    }
} 