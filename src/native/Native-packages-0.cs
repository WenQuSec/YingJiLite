using System;
using System.Runtime.InteropServices;
using System.Text;
namespace YingJiFile {
 public class Shape { public string Kind="Other"; public byte[] Key=new byte[0]; }
 public static class Probe {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetLongPathName(string path,StringBuilder output,uint length);
  public static string Canonical(string path) {StringBuilder b=new StringBuilder(32768);uint n=GetLongPathName(path,b,(uint)b.Capacity);return n>0&&n<b.Capacity?b.ToString():path;}
  static bool PE(byte[] b,long length) {
   if(b.Length<96||b[0]!=77||b[1]!=90)return false;
   int o=BitConverter.ToInt32(b,60);if(o<64||o>b.Length-26||BitConverter.ToUInt32(b,o)!=17744)return false;
   int machine=BitConverter.ToUInt16(b,o+4),sections=BitConverter.ToUInt16(b,o+6),opt=BitConverter.ToUInt16(b,o+20),magic=BitConverter.ToUInt16(b,o+24);
   return (machine==332||machine==34404||machine==43620)&&sections>0&&sections<=96&&opt>=96&&opt<=512&&(magic==267||magic==523)&&o+24L+opt+sections*40L<=length;
  }
  public static Shape Inspect(byte[] b,long length) {
   Shape s=new Shape();if(PE(b,length)){s.Kind="PE";return s;}if(b.Length<512)return s;
   byte[] known={77,90,144,0,3,0,0,0};
   for(int k=1;k<=8;k++) {byte[] key=new byte[k];for(int i=0;i<k;i++)key[i]=(byte)(b[i]^known[i]);bool match=true;
    for(int i=0;i<8;i++)if((b[i]^key[i%k])!=known[i]){match=false;break;}if(!match)continue;
    byte[] decoded=new byte[b.Length];for(int i=0;i<64;i++)decoded[i]=(byte)(b[i]^key[i%k]);int o=BitConverter.ToInt32(decoded,60);
    if(o<64||o>b.Length-26)continue;for(int i=o;i<o+26;i++)decoded[i]=(byte)(b[i]^key[i%k]);
    if(PE(decoded,length)){s.Kind="EncodedPE";s.Key=key;return s;}
   }return s;
  }
 }
}