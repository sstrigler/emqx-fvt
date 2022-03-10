package com.emqx.jwkserver.controller;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
public class jwkTest {
    public JSONObject testJson() {
        JSONObject object_keys = new JSONObject();
        JSONObject object_key = new JSONObject();
        object_key.put("p","4a1PrwJmvbq2R4dwmXsCclbwWTN4oRSZbq3VDfLr83g0WOZkEGkBvI7hTlq_RfYv7T2KBDC7e_MH8hkA4-QVUuHo31B50e0PCJVPqpzdlW9SfZrZaVJKAk9PeLP6A7UZbmJM5urGhJEOAbxO8RVHiyq45B6nSA9IpqxC3YeKpTk");
        object_key.put("kty","RSA");
        object_key.put("q","o8HqD4MWJnnABRC3A4mgHnS8ehtSyCLX1M3aLIk5m8UsvjdGLZ1_OzOLELY5iGY5N5giq1bHR9TOCSCKyBwsTcoDszcNmz_GaER4AyzI-6JAZJ0Xx2mIDz1BqLn989fLNRFVe5BpJq1pKkC9sNZw_100BCNJS17dWA8rFPOOlIc");
        object_key.put("d","Vn_HLThKL9iAYlqrG8yM0gVuY2tzyEptONf_69A8RrktxvUlPsl2XwfUd8fHSqdGjZrEmCjF6al5VkypwB3I-BKGH27bOaP-60DauzHnG_eYsk6glMPW2P9QvU5OLqHCrmpHiSACRBNRRdJszzBvGdu59D2JgI06gVpCGVUe8cM46gPwL6bUFuOyiIikgodKaVRCaJPA4lt_NpMuc0AC-kf6D52HxrsyQJmeG_5y1zzePAljcZQEwrSCN56igjaLwcSbaxFeKE7hUEqh6PNyW2y9lv1hdfwKfNo-rulhu9vLlRJvWkVbEzBC_peXWcu8HIkwtNxqEhIdOYhHFNZWkQ");
        object_key.put("e","AQAB");
        object_key.put("use","enc");
        object_key.put("kid","enc-1640929255");
        object_key.put("qi","G-HfU5DigPqsWPkivsaS2OnnKYPuGaC3yefqZh61B4BfVy_NILRFV4jh1gLWeLZOF4-dLdiLF6usdjEFZA_7wh2ZmqMqzy94XXXCA2I1R3MEOXOIuyHfrXh4TBm49T1fe-i93YCCJnh2q8uXM0ViutKjOg75MhnvFbzYcUZvYGg");
        object_key.put("dp","D9Kp-phNgdH8g8lgQLKaOlAUK_zq4UhjdZokjQTSPFDaQr1smKX0JDdUXr0IGiynsZeV_LM6AffJP9U29cOBJz2FqVqoH-riGfT2D_1Nn_OdMgdQZQ0K-Vx8MvdTeT0SWmX0BGDDqHnPJJoCYu7eBEjri7sGeYvwyRbc3VFqjCk");
        object_key.put("alg","RSA-OAEP-256");
        object_key.put("dq","jsfnAvty9r01NbVrPURkPene5ECqnyHyOfP6hNZpSm5TIs8i-2bVppK8cCfSZiFrRhP6NpaFTxY3RzH-j5gw8Opw63PXA0RKBGOemHYWD4Faz99A-ngDT_ZDJ5Bz4oaHAZBJjmFNrZGJnnOwcV2oTJ_BWNJDd9oQ-FTRZYUvDkU");
        object_key.put("n","kFxLu5kFFExujp6YFNvoVtl-fxHqeN29HzcPITP28dSSoRtgC8c2e9ARaqXunBkRQwt-meZQqFigrqXO3SOfAeF3M7-vvVfgBncrc0uKCrjZEteoqmm5j0WrFfTtWtgDftKyvOHsWhQnJfjVQ7juJV-CumD6HSHcW23qZJXPw6B0p-A7NCsRa3nIfffwbnwl320KXF__iRqHu4Jo2GiXPZts_w-_cEHNxLRE3q_Zb1jPXJRBTAorYYUPDOHMCqRGZzOlLbT6JjyT32SC1JQ8o3JVbfJNMtf_XdRYrHsmN0YzQ1Pe9_5BkNmcq7oX5MP39Nlgo-qpn-QA9ZpfYkAVDw");
        //array
        List<JSONObject> integers = Arrays.asList(object_key);
        object_keys.put("keys",integers);
        return object_keys;
    }

    @GetMapping("/jwk")
    public JSONObject getRequest(){
        return testJson();
    }


}
