/* Meta Pixel Code
   広告の効果を測るためのタグ。送るのは「ページを見た」「診断結果が出た」ことだけで、
   入力内容（URL・会社名・メールアドレス）は送らない。
   ページの設定（CSP）でインラインのスクリプトを止めているため、配布されたコードをこのファイルに置いている。
   自動の情報収集（ボタンのクリックやページの内容を読み取る機能）は止める。 */
!function(f,b,e,v,n,t,s)
{if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
n.queue=[];t=b.createElement(e);t.async=!0;
t.src=v;s=b.getElementsByTagName(e)[0];
s.parentNode.insertBefore(t,s)}(window, document,'script',
'https://connect.facebook.net/en_US/fbevents.js');
fbq('set', 'autoConfig', false, '1785599632652620');
fbq('init', '1785599632652620');
fbq('track', 'PageView');
/* End Meta Pixel Code */
