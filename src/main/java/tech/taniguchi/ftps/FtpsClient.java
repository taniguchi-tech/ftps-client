package tech.taniguchi.ftps;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * FtpsClientは、FTPSプロトコルを用いたFTPSサーバーとの通信に使用します。
 * ただし、現在このクライアントがサポートするのは、基礎的なコマンドに限定されており、一部使用できないコマンドが
 * 存在します。Implicitモードにも対応していません。
 * <p>
 * NASや無料ホームページサーバーに多い自己署名証明書(オレオレ証明書)に対応しています。
 * コンストラクタの第5引数でtrueを指定します。
 * <p>
 * スレッドセーフではありません。
 * <p>
 * 戻り値のないメソッドは、コマンドの実行が正常終了した場合そのまま終了し、異常終了した場合例外をスロー
 * します。
 * <p>
 * オブジェクトは、コンストラクタ引数よりログインに必要な情報を設定し、インスタンスを生成します。
 * その後、FTPSプロトコルを用いて実行したいメソッドが呼び出されたタイミングでクライアントは自動的にコネクション、
 * ログインを実行します。
 * したがって、コネクションやログインに関するメソッドはありません。
 * <p>
 * ファイル送信におけるサンプルコードを以下に示します。
 <pre><code>
     void store(List<String> uploadFileList) {
         FtpsClient ftps = new FtpsClient(HOST, PORT, USER_NAME, PASSWORD, false);
         try {
             ftps.cd("/dir");
             for (String uploadFile : uploadFileList) {
                 ftps.storFile(uploadFile, uploadFile);
             }
             ...

         } catch (Exception e) {
              throw new SampleRuntimeException(e);
         } finally {
              ftps.close();
         }
     }
 </code></pre>
 *
 * @author    d.taniguchi
 * @see       <a href="https://blog.taniguchi.tech/archives/31">taniguchi web logs<br>
 *            Apache Commons Net 3.6 FTPSClientが動かない！！諦めかけたそのとき、希望の光が見えることはなかった</a>
 */
public class FtpsClient implements Closeable {

    private static final Logger logger = Logger.getLogger(FtpsClient.class.getName());

    // 接続先ホスト名
    private final String HOST;
    // 接続先ポート番号
    private final int PORT;
    // ログインユーザー名
    private final String USER_NAME;
    // ログインパスワード
    private final String PASSWORD;
    // 自己署名証明書 (通称:オレオレ証明書) の可否
    private final boolean IGNORE_CERTIFICATE_FLG;

    // 制御通信用ソケット
    private Socket cSocket = null;
    // 制御用キャラクターストリーム
    private BufferedReader cBufReader = null;
    // 制御用プリントライター
    private PrintWriter cPrintWriter = null;

    // 転送通信用ソケット
    private Socket tSocket = null;
    // 転送通信用バイナリ入力ストリーム
    private BufferedInputStream tInputStream = null;
    // 転送通信用バイナリ出力ストリーム
    private BufferedOutputStream tOutputStream = null;
    // 転送通信用キャラクタ入力ストリーム
    private BufferedReader tBufferedReader = null;
    // 転送通信用キャラクタ出力ストリーム
    private PrintWriter tPrintWriter = null;

    // 自己署名証明書の場合使用するTrustManager定義
    private static final TrustManager IGNORE_ALL = new X509TrustManager() {
        @Override public X509Certificate[] getAcceptedIssuers() { return null; }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType){}
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType){}
    };

    /**
     * FTPSクライアントを構築します。
     *
     * @param   host                ホスト名、もしくはIPアドレス
     * @param   port                ポート番号 nullまたは空白の場合、デフォルトの21を使用
     * @param   userName            ユーザー名
     * @param   password            パスワード
     * @param   ignoreCertificate   自己署名証明書(オレオレ証明書)を許可する場合、trueを指定 (falseを推奨)
     */
    public FtpsClient(String host, String port, String userName, String password, boolean ignoreCertificate) {

        if(host == null || "".equals(host))
            throw new IllegalArgumentException("ホストアドレスが不正です。");

        int p = Integer.parseInt((port == null || "".equals(port)) ? "21" : port);
        if (p < 0 || p > 65535)
            throw new IllegalArgumentException("port番号が不正です。");

        if (userName == null || "".equals(userName))
            throw new IllegalArgumentException("ユーザーIDが空白です。");

        if (password == null || "".equals(password))
            throw new IllegalArgumentException("パスワードが空白です。");

        if (ignoreCertificate)
            logger.warning("自己署名証明書(オレオレ証明書)を許可する設定になっています。");

        HOST = host;
        PORT = p;
        USER_NAME = userName;
        PASSWORD = password;
        IGNORE_CERTIFICATE_FLG = ignoreCertificate;

    }

    /**
     *  change work directory
     *  <p>
     *  指定したパスへカレントディレクトリを移動します。
     *
     * @param    path
     * @throws   Exception
     */
    public void cd(String path) throws Exception {
        if(path == null || "".equals(path)) throw new IllegalArgumentException("パスが空白です。");
        sendCommand("CWD " + path, "250");
    }

    /**
     *  print work directory
     *  <p>
     *  カレントディレクトリのパスを返します。
     *
     * @return
     * @throws    Exception
     */
    public String pwd() throws Exception {
        return sendCommand("PWD", "257");
    }

    /**
     * rename
     * <p>
     * ファイル名を変更します。
     *
     * @param    from
     * @param    to
     * @throws   Exception
     */
    public void rename(String from, String to) throws Exception {
        sendCommand("RNFR " + from, "350");
        sendCommand("RNTO " + to, "250");
    }

    /**
     *  list
     *  <p>
     *  ファイルリストを取得します。
     *  <p>
     *  現在、ディレクトリ名とファイル名しか返さない実装になっています。
     *  クローン数を見て、パーミッション情報や、ユーザー、ユーザーグループ、ファイルサイズなども返せるよう
     *  実装追加します。
     *
     * @param    path
     * @return
     * @throws   Exception
     */
    public List<FtpsItem> ls(String path) throws Exception {

        /*
            TODO
            接続先FTPSサーバーがMLSDコマンドに対応している場合、MLSDコマンドを使用しファイルリストを取得する。
            LISTコマンドでは正確なファイル作成日時が取得できない。
        */

        openTransfer(false, "LIST " + ((path == null) ? "" : path), "150");
        List<FtpsItem> ret = new ArrayList<>();

        while(true) {
            String line = tBufferedReader.readLine();
            if (line == null) break;
            logger.fine("[転送受信] " + line);

            /*
             *      [LISTコマンド 変数:line に入る値の例]
             *
             *          drwx---r-x   6 ftp-user.jp ftpsUser123        4096 Aug 27 00:07 .
             *          drwx---r-x   6 ftp-user.jp ftpsUser123        4096 Aug 27 00:07 ..
             *          -rw----r--   1 ftp-user.jp ftpsUser123         138 Aug 24 14:04 .htaccess
             *          -rw-r--r--   1 ftp-user.jp ftpsUser123        8082 Aug 24 14:08 index.html
             *          drwxr-xr-x   4 ftp-user.jp ftpsUser123        4096 Aug 27 00:08 lib
             *
             *          -rw-rw-r--    1 ftp      ftp      58353164 Sep 04 20:32 12 ＬＯＮＥＬＹ　ＷＯＭＡＮ.wav
             *          -rw-rw-r--    1 ftp      ftp      13881548 Sep 04 20:32 13 キラーストリート.wav
             *          -rw-rw-r--    1 ftp      ftp      13881548 Sep 04 20:32 14 キラー   ;ストリート.wav
             *
             *
             *          cnt(要素)
             *          [0] : d/f ファイルアクセス権限
             *          [1] : ファイル数
             *          [2] : ユーザー名
             *          [3] : グループ
             *          [4] : ファイルサイズ
             *          [5] : 月
             *          [6] : 日
             *          [7] : 時分
             *          [8] : ディレクトリ/ファイル名
             */
            FtpsItem f = new FtpsItem();
            int cnt = 0;
            int start = 0;

            for (int current = 0; current < line.length() - 1; current++) {
                if (line.charAt(current) != ' ' && line.charAt(current + 1) == ' ') {

                    // 本来こっちにあるべき
                    //String elem = line.substring(start, current + 1); // start == current + 1 (一文字のの要素[1]とか)を想定せず

                    switch (cnt) {
                        // 要素[0] d/f ファイルアクセス権限
                        case 0:
                            String elem = line.substring(start, current + 1); // 要素増やす場合、switch分の前で実行

                            if(elem.startsWith("d")){
                                f.setTypeEnum(FtpsItem.TypeEnum.DIRECTORY); // Cuurent Dir, Parent Dirの場合、ファイル名を切り出した際に上書き
                            }else if(elem.startsWith("-")){
                                f.setTypeEnum(FtpsItem.TypeEnum.FILE);
                            }
                            break;
                        // 要素[1] ファイル数
                        // 　から
                        // 要素[7] 時分
                        // まで、めんどくさいので、実装省略 caseで[7]まで分岐、[8]はfor文を抜けた後に実装
                        // ここのループで行の要素数をカウントしているのでfor文を抜ける命令を入れないこと(ファイル名のスタート位置が不正となる)
                    }
                    cnt++;

                } else if ((cnt == 0 || cnt == 8) && line.charAt(current) == ' ' && line.charAt(current + 1) != ' ') {
                    start = current + 1;
                    if (cnt == 8) break;
                }
            }

            // 要素[8] : ファイル名
            String name = line.substring(start, line.length());
            if(".".equals(name))
                f.setTypeEnum(FtpsItem.TypeEnum.CURRENT_DIRECTORY);
            else if("..".equals(name))
                f.setTypeEnum(FtpsItem.TypeEnum.PARENT_DIRECTORY);
            f.setName(name);
            ret.add(f);
        }

        closeTransfer();
        getResponseCode("226");
        return ret;
    }

    /**
     * TODO
     *
     * MLSDコマンド　(RFC3659)
     *
     * 詳細なファイルの更新日付情報を含めたリストを取得する
     * なぜか対応していないFTPSサーバーアプリが散見される
     * ファイル名に半角スペース、複数半角スペース、";"が含まれている場合がある点に注意する
     *
     * @param path
     * @return
     * @throws Exception
     */
    private List<FtpsItem> mlsd(String path) throws Exception {

        /*
            [サーバーによって要素の順番が異なる]

            type=file;modify=20180830120022;size=37067564;UNIX.mode=0777;UNIX.owner=user;UNIX.group=users; music2.wav

            modify=20180826150741;perm=flcdmpe;type=cdir;unique=811U11680002;UNIX.group=1000;UNIX.mode=0705;UNIX.owner=1344958; .
            modify=20180826150741;perm=flcdmpe;type=pdir;unique=811U11680002;UNIX.group=1000;UNIX.mode=0705;UNIX.owner=1344958; ..
            modify=20180824050824;perm=adfrw;size=8082;type=file;unique=811U11680029;UNIX.group=1000;UNIX.mode=0644;UNIX.owner=1344958; index.html
        */
        /*
        openTransfer(false, "MLSD " + ((path == null) ? "" : path), "150");
         */

        return null;
    }

    /*
     * TODO change mode
     */
    /*
    public void chmod(String path) {
    }
    */

    /**
     *  make directory
     *  <p>
     *  ディレクトリを作成します。
     *
     * @param    path
     */
    public void mkDir(String path) throws  Exception {
        if(path == null || "".equals(path)) throw new IllegalArgumentException("パスが空白です。");
        sendCommand("MKD " + path, "257");
    }

    /**
     *  is file exists
     *  <p>
     *  ファイルが存在するかをboolean型で返します。
     *
     * @param    fullPath    ディレクトリのフルパス
     * @param    fileName    ファイル名
     * @return
     */
    public boolean isFileExists(String fullPath, String fileName) throws Exception {
        sendCommand("NOOP", "200");
        try {
            List<FtpsItem> l = ls(fullPath);
            for (FtpsItem f : l)
                if (fileName.equals(f.getName())) return true;
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     *  remove file
     *  <p>
     *  対象のファイルを削除します。
     *
     * @param    path
     * @return
     */
    public void rmFile(String path) throws Exception {
        if(path == null || "".equals(path)) throw new IllegalArgumentException("パスが空白です。");
        sendCommand("DELE " + path, "250");
    }

    /**
     *  remove directory recursion force
     *  <p>
     *  ディレクトリとその配下のディレクトリとファイルを再帰的に削除します。
     *
     * @param    fullPath
     */
    public void rmDirForce(String fullPath) throws Exception {
        if(fullPath == null || "".equals(fullPath)) throw new IllegalArgumentException("フルパスが空白です。");
        if(!fullPath.startsWith("/")) throw new IllegalArgumentException("フルパスが未指定です。");
        cd(fullPath);
        List<FtpsItem> l = ls(fullPath);
        for(FtpsItem f : l) {
            if(f.getTypeEnum()== FtpsItem.TypeEnum.DIRECTORY) {
                rmDirForce(fullPath + "/" + f.getName());
                cd(fullPath);
                rmDir(f.getName());
            }else if(f.getTypeEnum()== FtpsItem.TypeEnum.FILE) {
                rmFile(f.getName());
            }
        }
        if(!"/".equals(fullPath))
            rmDir(fullPath);
    }


    /**
     *  remove directory
     *  <p>
     *  対象のディレクトリが空の場合、そのディレクトリーを削除します。
     *
     * @param    path
     */
    public void rmDir(String path) throws Exception {
        if(path == null || "".equals(path)) throw new IllegalArgumentException("パスが空白です。");
        sendCommand("RMD " + path, "250");
    }

    /**
     * retr
     * <p>
     * ファイルを取得します。
     *
     * @param    ftpsPath
     * @param    localPath
     * @throws   Exception
     */
    public void retrFile(String ftpsPath, String localPath) throws Exception {
        retrFile(ftpsPath, new FileOutputStream(localPath));
    }

    /**
     * retr
     * <p>
     * ファイルを取得します。
     *
     * @param targetFtpsFilePath
     * @param fos
     * @throws Exception
     */
    public void retrFile(String targetFtpsFilePath, FileOutputStream fos) throws Exception {

        logger.info("*** [ファイル受信開始] "+ targetFtpsFilePath + " ***");
        openTransfer(true, "RETR "+ targetFtpsFilePath, "150");
        BufferedOutputStream fOut = null;

        try {

            fOut = new BufferedOutputStream(fos);
            int b;
            while((b = tInputStream.read()) != -1) {
                fOut.write(b);
            }
            fOut.flush();
            logger.fine("ファイル受信正常終了");

        }catch(Exception e) {
            logger.log(Level.WARNING, "ファイル受信異常終了", e);
            throw e;

        }finally {
            try {fOut.close();}catch(Exception e) {}
            closeTransfer();
        }

        getResponseCode("226");
        logger.info("*** [ファイル受信終了] "+ targetFtpsFilePath + " ***");
    }

    /**
     *  FTPSサーバー上のテキストファイル最初の一行を取得します。
     *
     * @param    path
     * @return
     * @throws   Exception
     */
    public String readFirstLine(String path) throws Exception {
        if(path == null || "".equals(path)) throw new NullPointerException();
        logger.info("*** [ファイル1行受信開始] "+ path + " ***");
        openTransfer(false, "RETR "+ path, "150");
        String line = tBufferedReader.readLine();
        closeTransfer();
        getResponseCode("226");
        logger.info("*** [ファイル1行受信終了] "+ path + " ***");
        return line;
    }

    /**
     * store
     * <p>
     * ファイル送信を行います。
     *
     * @param saveFtpsFilePath
     * @param targetLocalFilePath
     * @throws Exception
     */
    public void storFile(String saveFtpsFilePath, String targetLocalFilePath) throws Exception {
        storFile(saveFtpsFilePath, new FileInputStream(targetLocalFilePath));
    }

    /**
     * store
     * <p>
     * ファイル送信を行います。
     *
     * @param saveFtpsFilePath
     * @param fis
     * @throws Exception
     */
    public void storFile(String saveFtpsFilePath, FileInputStream fis) throws Exception {

        logger.info("*** [ファイル送信開始] "+ saveFtpsFilePath + " ***");
        openTransfer(true, "STOR " + saveFtpsFilePath, "150");
        BufferedInputStream fIn = null;

        try {

            fIn = new BufferedInputStream(fis);
            int b;
            while((b = fIn.read()) != -1) {
                tOutputStream.write(b);
            }
            tOutputStream.flush();
            logger.info("ファイル送信正常");

        } catch(Exception e) {
            logger.log(Level.WARNING, "ファイル送信異常", e);
            throw e;

        } finally {
            try {fIn.close();}catch(Exception e) {}
            closeTransfer();
        }

        getResponseCode("226");
        logger.info("*** [ファイル送信終了] "+ saveFtpsFilePath + " ***");
    }

    /**
     * 制御通信に接続しログインを行います。
     *
     * @throws Exception
     */
    private void openControl() throws Exception {

        try {

            //  制御通信が生きている場合
            if(cSocket != null && !cSocket.isClosed())
                return;

            // 制御通信が切断されていて、ソケットオブジェクトが生きている場合
            if(cSocket != null)
                close();

            logger.fine("FTPSサーバー制御通信・接続開始");
            cSocket = new Socket(HOST, PORT);
            cBufReader = new BufferedReader(new InputStreamReader(cSocket.getInputStream()));
            cPrintWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(cSocket.getOutputStream())));

            getResponseCode("220");
            sendCommand("AUTH TLS", "234"); // RFC-4217


            /*
             * 		[memo]
             *
             * 		SSL(TLS)ソケットで、デフォルト設定のままの接続を行う場合、以下の実装を使用すること。
             * 		今回は、自己署名証明書(オレオレ証明書)を許可する必要であったため、SSLContextを使用。
             *
             *
             *		SSLSocketFactory ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
             *		SSLSocket sslSocket = (SSLSocket)ssf.createSocket(HOST, dataTrnsportPort);
             *
             *		なお、以下の実装により、デフォルト設定と同じになる。
             *		context.init(null, null, null);
             *
             */
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, IGNORE_CERTIFICATE_FLG ? new TrustManager[] {IGNORE_ALL} : null, null);
            SSLSocketFactory ssf = context.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket)ssf.createSocket(cSocket, HOST, PORT, false);

            sslSocket.startHandshake();

            cSocket = sslSocket;
            cBufReader = new BufferedReader(new InputStreamReader(cSocket.getInputStream()));
            cPrintWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(cSocket.getOutputStream())));

            sendCommand("PBSZ 0", "200"); // RFC-4217
            sendCommand("PROT P", "200"); // RFC-4217
            sendCommand("USER " + USER_NAME, "331");
            sendCommand("PASS " + PASSWORD, "PASS ****" , "230");
            sendCommand("OPTS UTF8 ON", null); // UTF-8しかサポートしないサーバーはコマンドエラー
            sendCommand("TYPE I", "200"); // A:ASCII I:image(bin)

        } catch (SSLHandshakeException e) {
            logger.log(Level.SEVERE, "証明書チェックエラー", e);
            throw e;

        } catch (Exception e) {
            logger.log(Level.SEVERE, "サーバー接続異常終了", e);
            throw e;
        }
    }

    /**
     * Passiveモードでファイル転送通信の接続を行います。
     *
     * @param    isBinary        バイナリ/キャラクター
     * @param    cmd             コマンド
     * @param    expectedCode    正常終了レスポンスコード
     * @throws   Exception
     */
    private void openTransfer(boolean isBinary, String cmd, String expectedCode) throws Exception {

        openControl();
        logger.fine("FTPSサーバーファイル転送通信・接続開始");

        String[] ret = sendCommand("PASV", "227").split(",");
        int tPort = (Integer.parseInt(ret[4]) << 8) + Integer.parseInt(ret[5].substring(0,ret[5].indexOf(")")));
        logger.fine("[転送通信port番号] " + tPort);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, IGNORE_CERTIFICATE_FLG ? new TrustManager[] {IGNORE_ALL}: null, null);
        SSLSocketFactory ssf = context.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket)ssf.createSocket(HOST, tPort);

        sendCommand(cmd, expectedCode);
        sslSocket.startHandshake();
        tSocket = sslSocket;

        if (isBinary) {
            tInputStream = new BufferedInputStream(tSocket.getInputStream());
            tOutputStream = new BufferedOutputStream(tSocket.getOutputStream());
        } else {
            tBufferedReader = new BufferedReader(new InputStreamReader(tSocket.getInputStream()));
            tPrintWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(tSocket.getOutputStream())));
        }
    }

    /**
     * サーバーへコマンドを送信します。
     *
     * @param    cmd             FTPコマンド
     * @param    expectedCode    コマンド正常終了時のレスポンスコード。いずれのレスポンスでも異常としない場合、nullを設定
     * @return                   コマンド実行結果のレスポンスコードとメッセージ
     * @throws   Exception
     */
    private String sendCommand(String cmd, String expectedCode) throws Exception {
        return sendCommand(cmd, null, expectedCode);
    }

    /**
     * サーバーへコマンドを送信します。
     *
     * @param    cmd             FTPコマンド
     * @param    alter           ログ出力用代替文字
     * @param    expectedCode    コマンド正常終了時のレスポンスコード。いずれのレスポンスでも異常としない場合、nullを設定
     * @return                   コマンド実行結果のレスポンスコードとメッセージ
     * @throws   Exception
     */
    private String sendCommand(String cmd, String alter, String expectedCode) throws Exception {
        openControl();
        logger.fine("[制御送信] " + (alter == null ? cmd : alter));
        cPrintWriter.print(cmd + "\r\n");
        cPrintWriter.flush();
        return getResponseCode(expectedCode);
    }

    /**
     * サーバーからのレスポンスコードを受信します。
     *
     * @param     expectedCode    コマンド正常終了時のレスポンスコード。いずれのレスポンスでも異常としない場合、nullを設定
     * @return                    コマンド実行結果のレスポンスコードとメッセージ
     * @throws    Exception
     */
    private String getResponseCode(String expectedCode) throws Exception {
        String response = cBufReader.readLine();
        logger.fine("[制御受信] " + response);
        // FTPSサーバーから期待するレスポンスコードが得られなかった場合、実行時エラーをスロー
        if(expectedCode == null || response.startsWith(expectedCode))
            return response;
        else
            throw new RuntimeException("期待コードとレスポンスコード不一致 [期待コード:" + expectedCode + " レスポンスコード:" + response + "]");
    }

    /**
     * @inhertDoc
     */
    @Override
    public void close() {
        closeTransfer();
        closeControl();
    }

    /**
     * ファイル転送通信と、ファイル転送通信用ストリームをクローズします。
     */
    private void closeTransfer() {

        try {
            tInputStream.close();
        }catch(Exception e){}

        try {
            tOutputStream.close();
        }catch(Exception e){}

        try {
            tBufferedReader.close();
        }catch(Exception e){}

        try {
            tPrintWriter.close();
        }catch(Exception e){}

        try {
            if(!tSocket.isClosed())
                tSocket.close();
        }catch(Exception e){}

        logger.fine("ファイル転送通信クローズ完了");
    }

    /**
     * 制御通信と、制御通信用ストリームをクローズします。
     */
    private void closeControl() {

        try {
            if(!cSocket.isClosed())
                sendCommand("QUIT", null);
        } catch (Exception e) {}

        try {
            cBufReader.close();
        } catch (Exception e) {}

        try {
            cPrintWriter.close();
        } catch (Exception e) {}

        try {
            if(!cSocket.isClosed())
                cSocket.close();
        } catch (Exception e) {}

        logger.fine("制御通信クローズ完了");
    }
}
