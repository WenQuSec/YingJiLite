using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace YingJiRuntime {
 public static class Payload {
  static Dictionary<string,string> code;
  public static Dictionary<string,string> Load(){
   if(code!=null)return new Dictionary<string,string>(code,StringComparer.OrdinalIgnoreCase);
   using(var source=Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.bin"))
   using(var zip=new GZipStream(source,CompressionMode.Decompress))
   using(var reader=new StreamReader(zip,Encoding.UTF8)){
    var serializer=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};
    code=serializer.Deserialize<Dictionary<string,string>>(reader.ReadToEnd());
   }
   return new Dictionary<string,string>(code,StringComparer.OrdinalIgnoreCase);
  }
  public static string GetHash(string name){var scripts=Load();if(!scripts.ContainsKey(name))return "";var enc=new UTF8Encoding(true);var content=enc.GetBytes(scripts[name]);var preamble=enc.GetPreamble();var all=new byte[preamble.Length+content.Length];Buffer.BlockCopy(preamble,0,all,0,preamble.Length);Buffer.BlockCopy(content,0,all,preamble.Length,content.Length);using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(all)).Replace("-","");}
 }
 public static class Collector {
  public static int Run(string output,int hours,string inputEvidence,Action<string> progress){
   Directory.CreateDirectory(output);
   string log=Path.Combine(output,"launcher.log");object logLock=new object();
   Action<string> emit=s=>{if(String.IsNullOrEmpty(s))return;lock(logLock){File.AppendAllText(log,s+Environment.NewLine,new UTF8Encoding(true));}if(progress!=null)progress(s);};
   try{
    var scripts=Payload.Load();
    using(var space=RunspaceFactory.CreateRunspace(InitialSessionState.CreateDefault())){
     space.ApartmentState=System.Threading.ApartmentState.STA;space.ThreadOptions=PSThreadOptions.ReuseThread;space.Open();
     space.SessionStateProxy.SetVariable("IRCode",scripts);
     space.SessionStateProxy.SetVariable("IRLauncher",Assembly.GetExecutingAssembly().Location);
     using(var setup=PowerShell.Create()){
      setup.Runspace=space;setup.AddScript("function Get-IRScript([string]$name) { if(!$IRCode.ContainsKey($name)){throw ('内嵌模块缺失：'+$name)}; [scriptblock]::Create($IRCode[$name]) }");setup.Invoke();if(setup.HadErrors)throw new Exception("内嵌运行空间初始化失败");
     }
     using(var ps=PowerShell.Create()){
      ps.Runspace=space;
      ps.Streams.Information.DataAdded+=(s,e)=>emit(Convert.ToString(ps.Streams.Information[e.Index].MessageData));
      ps.Streams.Error.DataAdded+=(s,e)=>emit("诊断："+ps.Streams.Error[e.Index].ToString());
      ps.AddScript(scripts["engine.ps1"],false).AddParameter("Output",output).AddParameter("Hours",hours);
      if(!String.IsNullOrEmpty(inputEvidence))ps.AddParameter("InputEvidence",inputEvidence);
      string ioc=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"ioc.json");if(File.Exists(ioc))ps.AddParameter("IocFile",ioc);
      var result=ps.Invoke();foreach(var item in result)if(item!=null)emit(item.ToString());
      if(ps.InvocationStateInfo.State==PSInvocationState.Failed)throw new Exception("取证运行失败",ps.InvocationStateInfo.Reason);
     }
    }
    if(!File.Exists(Path.Combine(output,"report.html"))||!File.Exists(Path.Combine(output,"report-view.json")))throw new Exception("报告未完整生成");
    var manifest=new List<object>();
    foreach(string path in Directory.GetFiles(output)){
     if(Path.GetFileName(path)=="manifest.json")continue;
     string hash;using(var file=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))using(var sha=SHA256.Create()){hash=BitConverter.ToString(sha.ComputeHash(file)).Replace("-","");}
     manifest.Add(new{Name=Path.GetFileName(path),Size=new FileInfo(path).Length,SHA256=hash});
    }
    File.WriteAllText(Path.Combine(output,"manifest.json"),new JavaScriptSerializer().Serialize(manifest),new UTF8Encoding(true));
    return 0;
   }catch(Exception e){emit("检查失败："+e.ToString());File.WriteAllText(Path.Combine(output,"failure.log"),e.ToString(),new UTF8Encoding(true));return 1;}
  }
 }
}
