package com.example.didjwtdemo.controller;

import com.example.didjwtdemo.service.DidKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Controller
public class DidKeyController {
    @Autowired
    private DidKeyService didKeyService;

    private KeyPair lastKeyPair; // Demo 用，實際應用請用 session 或資料庫

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("did", null);
        return "index";
    }

    @PostMapping("/generate")
    public String generateKey(Model model) throws Exception {
        lastKeyPair = didKeyService.generateP256KeyPair();
        String did = didKeyService.getDidFromPublicKey(lastKeyPair.getPublic());
        model.addAttribute("did", did);
        model.addAttribute("publicKey", Base64.getEncoder().encodeToString(lastKeyPair.getPublic().getEncoded()));
        model.addAttribute("privateKey", Base64.getEncoder().encodeToString(lastKeyPair.getPrivate().getEncoded()));
        return "index";
    }

    @PostMapping("/setCustomKeys")
    public String setCustomKeys(@RequestParam String publicKeyInput, @RequestParam String privateKeyInput, Model model) throws Exception {
        try {
            // 從 Base64 字串重建 KeyPair
            byte[] pubBytes = Base64.getDecoder().decode(publicKeyInput);
            byte[] privBytes = Base64.getDecoder().decode(privateKeyInput);
            
            java.security.spec.X509EncodedKeySpec pubSpec = new java.security.spec.X509EncodedKeySpec(pubBytes);
            java.security.spec.PKCS8EncodedKeySpec privSpec = new java.security.spec.PKCS8EncodedKeySpec(privBytes);
            
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
            PublicKey publicKey = kf.generatePublic(pubSpec);
            PrivateKey privateKey = kf.generatePrivate(privSpec);
            
            lastKeyPair = new KeyPair(publicKey, privateKey);
            String did = didKeyService.getDidFromPublicKey(lastKeyPair.getPublic());
            model.addAttribute("did", did);
            model.addAttribute("publicKey", publicKeyInput);
            model.addAttribute("privateKey", privateKeyInput);
            model.addAttribute("success", "自訂金鑰設定成功");
        } catch (Exception e) {
            model.addAttribute("error", "金鑰格式錯誤: " + e.getMessage());
        }
        return "index";
    }

    @PostMapping("/sign")
    public String sign(@RequestParam("keys") java.util.List<String> keys, @RequestParam("values") java.util.List<String> values, Model model) throws Exception {
        if (lastKeyPair == null) {
            model.addAttribute("error", "請先產生 DID key 或設定自訂金鑰");
            return "index";
        }
        // 組成 payload JSON
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        for (int i = 0; i < keys.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(keys.get(i))).append("\":");
            sb.append("\"").append(escapeJson(values.get(i))).append("\"");
        }
        sb.append("}");
        String payload = sb.toString();
        String jwt = didKeyService.createJwt(payload, lastKeyPair.getPrivate(), lastKeyPair.getPublic());
        model.addAttribute("did", didKeyService.getDidFromPublicKey(lastKeyPair.getPublic()));
        model.addAttribute("publicKey", java.util.Base64.getEncoder().encodeToString(lastKeyPair.getPublic().getEncoded()));
        model.addAttribute("privateKey", java.util.Base64.getEncoder().encodeToString(lastKeyPair.getPrivate().getEncoded()));
        model.addAttribute("signature", jwt);
        // 將 key/value 組成顯示訊息
        StringBuilder msgSb = new StringBuilder();
        for (int i = 0; i < keys.size(); i++) {
            msgSb.append(keys.get(i)).append(": ").append(values.get(i));
            if (i < keys.size() - 1) msgSb.append("\n");
        }
        model.addAttribute("message", msgSb.toString());
        String jwtPayload = didKeyService.parseJwtPayload(jwt);
        String jwtHeader = didKeyService.parseJwtHeader(jwt);
        model.addAttribute("jwtPayload", jwtPayload);
        model.addAttribute("jwtHeader", jwtHeader);
        return "index";
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @PostMapping("/verify")
    public String verify(@RequestParam String message, @RequestParam String signature, Model model) throws Exception {
        if (lastKeyPair == null) {
            model.addAttribute("error", "請先產生 DID key 或設定自訂金鑰");
            return "index";
        }
        // 驗證 JWT 簽章
        String[] parts = signature.split("\\.");
        boolean valid = false;
        String jwtPayload = null;
        if (parts.length == 3) {
            String signingInput = parts[0] + "." + parts[1];
            byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
            valid = didKeyService.verify(signingInput.getBytes(), sigBytes, lastKeyPair.getPublic());
            jwtPayload = didKeyService.parseJwtPayload(signature);
            // 檢查 payload 的 msg 是否等於 message
            if (valid && jwtPayload != null && jwtPayload.contains("\"msg\":")) {
                String msgValue = jwtPayload.replaceAll(".*\"msg\":\\s*\"(.*?)\".*", "$1");
                valid = message.equals(msgValue);
            }
        }
        model.addAttribute("did", didKeyService.getDidFromPublicKey(lastKeyPair.getPublic()));
        model.addAttribute("publicKey", Base64.getEncoder().encodeToString(lastKeyPair.getPublic().getEncoded()));
        model.addAttribute("privateKey", Base64.getEncoder().encodeToString(lastKeyPair.getPrivate().getEncoded()));
        model.addAttribute("signature", signature);
        model.addAttribute("message", message);
        String jwtHeader = signature.split("\\.").length == 3 ? didKeyService.parseJwtHeader(signature) : null;
        model.addAttribute("jwtHeader", jwtHeader);
        model.addAttribute("jwtPayload", jwtPayload);
        model.addAttribute("verifyResult", valid ? "驗章成功" : "驗章失敗");
        return "index";
    }
} 