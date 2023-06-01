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
 클라이언트(js)      <------------------->      서버(java)
 TEA - RSA 순 암호화                            RSA-TEA 순 복호화
    js에서 Tea를 이용한 암호화를 진행 후 이것을 RSA 암호화하여 서버에 넘긴다.
    서버에서는 이를 받아 복호화 진행하게 된다. ( 프론트는 코드 예시만 작성하고 값은 하드코딩값으로 대체한다.)
    
 */

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class RsaAndTea {
    // 클라이언트에서 아래 값이 넘어왔다고 가정한다. tea 암호화에 사용된 key값은 'test'
    static String clientId = "id1234";
    static String clientPwd = "pwd1234";
    static String key = "RsaAndTeaTest1234";
    public static void main(String[] args) {
        try {
          

            TEA tea = new TEA(key.getBytes());
            
            // 상황 1. 클라이언트가 도메인에 접속 이후 로그인 시도 할 경우
            // RSA 키값 생성 키값 중 퍼블릭 값을 클라이언트에게 넘긴다.
            RSA rsa = RSA.getInstance();
            rsa.init();
            // 실제 사용시에 세션또는 DB 등에 개인키를 따로 저장한다.
            // session.setAttribute("privateKey", rsa.getPrivateKey(););
            
            // 상황2 id와 pwd를 암호화한다. 실제로는 JS가 이를 담당한다.
            // TEA 암호화
            clientId = tea.encrypt(clientId);   // XVwvQQ/dm04=
            clientPwd = tea.encrypt(clientPwd); // UwAorJi8YaI
            // RSA 암호화 
            // publicKeyString 형태를 사용할때는 publicKey를 문자열 형태로 다른곳에 보낼때 사용한다.
            String publicKeyString = rsa.encodeBase64ToString(rsa.getPublicKey().getEncoded());
            // publicKeyString을 받은 후 사용할 때는 다시 Base64로 디코딩해줘야 한다. 여기 수정해야함
            PublicKey publicKey = rsa.convertStrToPubKey(rsa.decodeBase64(publicKeyString));
            clientId = rsa.byteArrayToHex(rsa.encryptRsa(clientId, publicKey));
            clientPwd = rsa.byteArrayToHex(rsa.encryptRsa(clientPwd, rsa.getPublicKey()));

            // 상황3 클라이언트에게 암호화 된 아이디와 비밀번호를 받은 경우
            // 클라이언트에게 받은 값을 복호화한다.
            // 세션 또는 DB로 부터 생성된 개인키를 가져온다.
            // PrivateKey privateKey = session.getAttribute("privateKey"); 

            // RSA 복호화
            clientId = rsa.decryptRsa(rsa.getPrivateKey(), (rsa.hexToByteArray(clientId)));
            clientPwd = rsa.decryptRsa(rsa.getPrivateKey(), rsa.hexToByteArray(clientPwd));            

            // TEA 복호화
            clientId = tea.decrypt(clientId);
            clientPwd = tea.decrypt(clientPwd);

            System.out.println(clientId);
            System.out.println(clientPwd);

        } catch (NoSuchAlgorithmException nae) {
            nae.printStackTrace();
        } catch(InvalidKeySpecException ise) {
            ise.printStackTrace();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

   
    
    
}

