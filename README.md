# filechecksums - ファイルチェックサム記録・比較ツール

## filechecksums とは

filechecksums は、ファイルの破損検出の為のツールです。
あらかじめファイルのチェックサムを計算しておき、あとで比較することで、
ファイルが破損していないかを調べます。

ストレージをお引越しするときに、コピー元のデータが破損していないかの確認や、
正しくコピーできたかを確認することなどを想定しています。

md5sum と同じようなツールですが、以下の点が違います。

* md5 だけでなく、 sha256 を同時に計算して記録・比較できます。
* ファイルの更新時刻を記録していますので、更新されたファイルのチェックサムを更新することができます。
* ファイルの更新時刻・サイズを記録していますので、チェックサムが一致しなかった場合の参考にできます。
* 対象のファイルはコマンドラインでの指定ではなく、対象ディレクトリ以下の全ファイルとなります。
