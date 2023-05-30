/* 
 * 대칭키 / 비대칭(공개키) 암호화
 * 
 * 대칭키 암호화 방식은 암복호화에 사용하는 키가 동일한 암호화 방식 그와 달리 공개키 암호화 방식은
 * 암복호화에 사용하는 키가 서로 다르다 이러한 이유로 비대칭키 암호화라고도 한다.
 * 
 * 1) 대칭키 - 대칭키 암호화 방식은 암복호화에 사용하는 키가 동일한 암호화 방식
 *  대칭키는 암복호화키가 동일하며 해당 키를 아는사람만이 문서를 복호화해 볼 수 있게된다. *  
 *  예) DES, 3DES, AES, SEED, ARIA 등
 * 
 *  공개키 암호화 방식에 비해 속도가 빠르다는 장점이 있지만, 키를 교환해야한다는 문제 (키 배송 문제)가 발생한다.
 *  이로 인해 키를 교환하는 중 키가 탈취될 수 있는 문제도 있고 
 *  사람이 증가할수록 전부 따로따로 키교환을 해야하기 때문에 관리해야 할 키가 방대하게 많아진다.
 * 
 * 2) 공개키 - 공개키 암호화 방식은 암복호화에 사용하는 키가 서로 다르다 이러한 이유로 비대칭키 암호화라고도 한다.
 *  대칭키의 문제를 보완하기 위한 방식으로 이름 그대로 키가 공개되어있기 때문에 키를 교환할 필요가 없어지며 
 *  공개키는 모든 사람이 접근 가능한 키이고 개인키는 각 사용자만이 가지고 있는 키이다. 
 *  예를 들어, A가 B에게 데이터를 보낸다고 할 때, A는 B의 공개키로 암호화한 데이터를 보내고 B는 본인의 개인키로 
 *  해당 암호화된 데이터를 복호화해서 보기 때문에 암호화된 데이터는 B의 공개키에 대응되는 개인키를 갖고 있는 B만이 볼 수 있게 되는 것이다.  * 
 *  예) Diffie-Hellman, RSA, DSA, ECC
 * 
 *  키 전달 문제를 해결하여 더 안전하지만, 암호화와 복호화를 위해 복잡한 수학 연산을 수행하기 때문에 대칭키 알고리즘에 비해 속도가 느리다는 단점이 있다.
 */


/* 
 클라이언트(js) <-------------------> 서버(java)
    js에서 Tea를 이용한 암호화를 진행 후 이것을 RSA 암호화하여 서버에 넘긴다.
    서버에서는 이를 받아 복호화 진행하게 된다. ( 프론트는 코드 예시만 작성하고 값은 하드코딩값으로 대체한다.)
    
 */

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class RsaAndTea {
    // 클라이언트에서 아래 값이 넘어왔다고 가정한다. tea 암호화에 사용된 key값은 'test'
    String clientkId = "26406e045756a7e272ebfadb7ac784be82db9bbd48f95218ce6cc97cd842201fd7d05b0ea872e9e17c659abde9d6be57e3c2b914d62ce5e4b0cbd0e7847b161a7a7af4f856649a172febcbee558525af994727d11cad648525b29a7e3fd66cc0ca7e62733b70c7e4b5f1b92c1e2228faf10d8398c103d109efee530e3aa98051";
    String clientPwd = "a340649726665f887bc19e69dca31aa929a311e061defe47b814d2c4f1741ed5386cc205201474386a3e615a94863fd1e646e800bda0c5839dfa0fea6a2fd37a1051c5dd31892adf11e6a453d610591c92c716876283634f0544bce750503925e3fb10a03971516358975ec6aebcaba36a94e72794b4c424d47a9a224f6f6454";

    public static void main(String[] args) {
        try {
            // RSA
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);

            KeyPair keyPair = generator.genKeyPair();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 실제 사용시에 세션또는 DB 등에 개인키를 따로 저장한다.
            // session.setAttribute("privateKey", privateKey);

            // 생성한 공개키를 공개키로서 지정한다.
            RSAPublicKeySpec publicKeySpec = (RSAPublicKeySpec) keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);

            // 클라이언트와 공유할 공개키를 String 형태로 저장한다.
            String publicKeyModulus = publicKeySpec.getModulus().toString(16);
            String publicKeyExponent = publicKeySpec.getPublicExponent().toString(16);


            // TEA
        } catch (NoSuchAlgorithmException nae) {
            nae.printStackTrace();
        } catch(InvalidKeySpecException ise) {
            ise.printStackTrace();
        }
    }
}
