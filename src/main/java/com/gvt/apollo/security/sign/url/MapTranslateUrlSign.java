package com.gvt.apollo.security.sign.url;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.TreeMap;

/**
 * 将集合M内非空参数值的参数按照参数名ASCII码从小到大排序（字典序）格式（即key1=value1&key2=value2…）拼接成字符串stringA。
 * @author jiaozi<liaomin @ gvt861.com>
 * @since JDK8
 * Creation time：2019/8/8 14:04
 */
public class MapTranslateUrlSign extends AbstractUrlParamSign {
    private Map<String,String> jsonMap;
    private PrivateKey privateKey;
    public static final String SIGN_KEY="sign";
    public static final String RANDOMSTR_KEY="random_str";
    public static final String APPID_KEY="appid";
    public MapTranslateUrlSign(PrivateKey privateKey,Map<String,String> jsonMap) {
        Map<String, String> treeMap = new TreeMap<String, String>();
        treeMap.putAll(jsonMap);
        this.jsonMap = treeMap;
        this.privateKey = privateKey;
    }

    @Override
    public Object signData() {
        return this.jsonMap;
    }
    @Override
    public PrivateKey getPrivateKey() {
        return this.getPrivateKey();
    }
    @Override
    public String url() {
        StringBuffer paramUrl=new StringBuffer();
        jsonMap.entrySet().forEach(entry->{
            if(!SIGN_KEY.equals(entry.getKey())) {
                paramUrl.append(entry.getKey() + "=" + entry.getValue() + "&");
            }
        });
        return paramUrl.toString();
    }

    @Override
    public boolean allowdSign() {
        if(!this.jsonMap.containsKey(RANDOMSTR_KEY) || !this.jsonMap.containsKey(APPID_KEY)) {
            return false;
        }
        return true;
    }
}
