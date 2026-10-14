using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Reflection;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Markup;
using System.Windows.Interop;
using Microsoft.Win32;

class YingJi : Window {
    Grid screen;
    Button scan,report,folder;
    TextBox log;
    TextBlock status,statusHint,outputText;
    ComboBox window;
    ProgressBar progress;
    string lastOutput;
    bool running,logOpen;
    Dictionary<string,object> icons;
    const double DesignWidth=734,DesignHeight=876;
    public YingJi(){
        Title="应急·轻 1.13 | 问渠安全实验室";
        ResizeMode=ResizeMode.CanMinimize;WindowStyle=WindowStyle.None;AllowsTransparency=true;
        Background=Brushes.Transparent;WindowStartupLocation=WindowStartupLocation.CenterScreen;
        screen=(Grid)XamlReader.Parse(ReadResource("Ui.xaml"));
        Content=new Viewbox{Stretch=Stretch.Uniform,StretchDirection=StretchDirection.Both,Child=screen};
        icons=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(ReadResource("icons.json"));
        Icon=ResourceImage("app.ico");Find<Image>("TitleIcon").Source=Icon;Find<Image>("BrandLogo").Source=ResourceImage("brand-on-light.png");
        scan=Find<Button>("ScanButton");report=Find<Button>("ReportButton");folder=Find<Button>("FolderButton");
        log=Find<TextBox>("LogText");status=Find<TextBlock>("StatusText");statusHint=Find<TextBlock>("StatusHint");outputText=Find<TextBlock>("OutputText");window=Find<ComboBox>("WindowSelect");progress=Find<ProgressBar>("ScanProgress");
        scan.Content=ButtonContent("Search","一键检查",Colors.White,24);
        report.Content=ButtonContent("FileText","查看报告",Color.FromRgb(24,48,68),23);
        folder.Content=ButtonContent("FolderClosed","证据目录",Color.FromRgb(24,48,68),24);
        SetIcon("StateIcon","Monitor",32);SetIcon("OsIcon","Layers",15);SetIcon("HostIcon","Monitor",15);SetIcon("ScopeIcon","Globe",15);SetIcon("OutputIcon","FolderClosed",15);SetIcon("LogIcon","FileText",21);SetIcon("LogChevron","ChevronDown",17);
        Find<Button>("MinimizeButton").Content=IconElement("Minus",18,Colors.White);
        Find<Button>("CloseButton").Content=IconElement("X",18,Colors.White);
        Find<TextBlock>("HostText").Text=Environment.MachineName;Find<TextBlock>("HostText").ToolTip=Environment.MachineName;
        Find<TextBlock>("OsText").Text=OsName();Find<TextBlock>("OsText").ToolTip=Find<TextBlock>("OsText").Text;
        outputText.ToolTip=DefaultRoot();
        Find<Button>("MinimizeButton").Click+=delegate{WindowState=WindowState.Minimized;};Find<Button>("CloseButton").Click+=delegate{Close();};
        Find<System.Windows.Controls.Border>("TitleBar").MouseLeftButtonDown+=delegate(object sender,MouseButtonEventArgs e){if(e.ClickCount==1&&e.OriginalSource is TextBlock || e.ClickCount==1&&e.OriginalSource is System.Windows.Controls.Border){DragMove();FitCurrentMonitor();}};
        Find<Button>("LogToggle").Click+=delegate{ToggleLog();};
        scan.Click+=async delegate{await Scan();};
        report.Click+=delegate{Process.Start(new ProcessStartInfo(Path.Combine(lastOutput,"report.html")){UseShellExecute=true});};
        folder.Click+=delegate{Process.Start(new ProcessStartInfo(lastOutput){UseShellExecute=true});};
        Closing+=delegate(object sender,CancelEventArgs e){if(running){e.Cancel=true;MessageBox.Show(this,"检查正在进行，完成后可关闭。","应急·轻");}};
        SourceInitialized+=delegate{HwndSource.FromHwnd(new WindowInteropHelper(this).Handle).AddHook(FixedWindowHook);FitCurrentMonitor();};
        FitToWorkArea(SystemParameters.WorkArea.Width,SystemParameters.WorkArea.Height);
    }
    T Find<T>(string name) where T:class{return (T)screen.FindName(name);}
    static string ReadResource(string name){using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream(name))using(var r=new StreamReader(s,Encoding.UTF8)){return r.ReadToEnd();}}
    static BitmapSource ResourceImage(string name){using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream(name)){var image=BitmapFrame.Create(s,BitmapCreateOptions.None,BitmapCacheOption.OnLoad);image.Freeze();return image;}}
    static string OsName(){try{using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")){string name=Convert.ToString(key.GetValue("ProductName"));int build;if(Int32.TryParse(Convert.ToString(key.GetValue("CurrentBuildNumber")),out build)&&build>=22000)name=name.Replace("Windows 10","Windows 11");return name;}}catch{return "Windows";}}
    void SetIcon(string control,string name,double size){Find<ContentControl>(control).Content=IconElement(name,size,Color.FromRgb(85,112,132));}
    UIElement ButtonContent(string name,string text,Color color,double size){var row=new StackPanel{Orientation=Orientation.Horizontal};var icon=IconElement(name,size,color);((FrameworkElement)icon).Margin=new Thickness(0,0,14,0);row.Children.Add(icon);row.Children.Add(new TextBlock{Text=text,VerticalAlignment=VerticalAlignment.Center});return row;}
    UIElement IconElement(string name,double size,Color color){
        var group=new GeometryGroup();
        foreach(object node in (System.Collections.IEnumerable)icons[name]){
            var pair=(System.Collections.IList)node;var attrs=(Dictionary<string,object>)pair[1];string kind=(string)pair[0];
            Func<string,double> n=k=>Convert.ToDouble(attrs[k],System.Globalization.CultureInfo.InvariantCulture);
            if(kind=="path")group.Children.Add(Geometry.Parse((string)attrs["d"]));
            else if(kind=="circle")group.Children.Add(new EllipseGeometry(new Point(n("cx"),n("cy")),n("r"),n("r")));
            else if(kind=="rect")group.Children.Add(new RectangleGeometry(new Rect(n("x"),n("y"),n("width"),n("height")),attrs.ContainsKey("rx")?n("rx"):0,attrs.ContainsKey("rx")?n("rx"):0));
            else if(kind=="line")group.Children.Add(new LineGeometry(new Point(n("x1"),n("y1")),new Point(n("x2"),n("y2"))));
        }
        var canvas=new Canvas{Width=24,Height=24};canvas.Children.Add(new System.Windows.Shapes.Path{Data=group,Stroke=new SolidColorBrush(color),StrokeThickness=1.8,StrokeStartLineCap=PenLineCap.Round,StrokeEndLineCap=PenLineCap.Round,StrokeLineJoin=PenLineJoin.Round});
        return new Viewbox{Width=size,Height=size,Child=canvas,VerticalAlignment=VerticalAlignment.Center};
    }
    void ToggleLog(){logOpen=!logOpen;Find<RowDefinition>("LogRow").Height=new GridLength(logOpen?120:0);Find<System.Windows.Controls.Border>("LogPanel").Visibility=logOpen?Visibility.Visible:Visibility.Collapsed;Find<TextBlock>("LogState").Text=logOpen?"（已展开）":"（已折叠）";SetIcon("LogChevron",logOpen?"ChevronUp":"ChevronDown",17);}
    internal void FitToWorkArea(double width,double height){double factor=Math.Min(1,Math.Min((width-40)/DesignWidth,(height-40)/DesignHeight));factor=Math.Max(.1,factor);Width=DesignWidth*factor;Height=DesignHeight*factor;}
    [StructLayout(LayoutKind.Sequential)] struct RECT{public int Left,Top,Right,Bottom;}
    [StructLayout(LayoutKind.Sequential)] struct MONITORINFO{public int Size;public RECT Monitor,Work;public uint Flags;}
    [DllImport("user32.dll")]static extern IntPtr MonitorFromWindow(IntPtr window,uint flags);
    [DllImport("user32.dll")]static extern bool GetMonitorInfo(IntPtr monitor,ref MONITORINFO info);
    IntPtr FixedWindowHook(IntPtr hwnd,int message,IntPtr wParam,IntPtr lParam,ref bool handled){if(message==0x112&&(((int)wParam&0xfff0)==0xf000||((int)wParam&0xfff0)==0xf030)){handled=true;}if(message==0x2e0){Dispatcher.BeginInvoke((Action)FitCurrentMonitor);}return IntPtr.Zero;}
    void FitCurrentMonitor(){var helper=new WindowInteropHelper(this);if(helper.Handle==IntPtr.Zero)return;var info=new MONITORINFO{Size=Marshal.SizeOf(typeof(MONITORINFO))};if(!GetMonitorInfo(MonitorFromWindow(helper.Handle,2),ref info))return;var source=HwndSource.FromHwnd(helper.Handle);double dpi=source.CompositionTarget.TransformToDevice.M11;FitToWorkArea((info.Work.Right-info.Work.Left)/dpi,(info.Work.Bottom-info.Work.Top)/dpi);Left=Math.Max(info.Work.Left/dpi,Math.Min(Left,info.Work.Right/dpi-Width));Top=Math.Max(info.Work.Top/dpi,Math.Min(Top,info.Work.Bottom/dpi-Height));}
    void Append(string text){if(text==null)return;Dispatcher.BeginInvoke((Action)delegate{log.AppendText(text+Environment.NewLine);if(logOpen)log.ScrollToEnd();});}
    void LoadAssessment(string output){var view=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(output,"report-view.json"),Encoding.UTF8));string level=Convert.ToString(view["AssessmentLevel"]);status.Text=Convert.ToString(view["AssessmentLabel"]);status.Foreground=new SolidColorBrush(level=="red"?Color.FromRgb(200,58,67):level=="green"?Color.FromRgb(22,128,92):Color.FromRgb(166,107,0));statusHint.Text=Convert.ToString(view["IssueCount"])+" 组异常 · "+Convert.ToString(view["Summary"]);}
        static string NewOutput(string root) { return Path.Combine(root,"IR-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,8)); }
    internal static string DefaultRoot(){return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),"应急轻报告");}
    async Task Scan(){
        running=true;scan.IsEnabled=window.IsEnabled=report.IsEnabled=folder.IsEnabled=false;progress.Visibility=Visibility.Visible;progress.IsIndeterminate=true;
        status.Text="正在检查";status.Foreground=new SolidColorBrush(Color.FromRgb(24,48,68));statusHint.Text="采集文件、持久化与网络证据，通常数分钟。";log.AppendText(Environment.NewLine+"—— 开始新一轮取证 ——"+Environment.NewLine);
        try{
            lastOutput=NewOutput(DefaultRoot());outputText.Text=Path.GetFileName(lastOutput);outputText.ToolTip=lastOutput;
            int hours=new int[]{24,72,168}[window.SelectedIndex];
            int code=await Task.Run(()=>YingJiRuntime.Collector.Run(lastOutput,hours,null,Append));
            if(code!=0)throw new Exception("检查未完整完成，已有证据保留。");
            report.IsEnabled=folder.IsEnabled=File.Exists(Path.Combine(lastOutput,"report.html"));LoadAssessment(lastOutput);Process.Start(new ProcessStartInfo(Path.Combine(lastOutput,"report.html")){UseShellExecute=true});
        }catch(Exception e){status.Text="检查未完整完成";status.Foreground=new SolidColorBrush(Color.FromRgb(166,107,0));statusHint.Text="已有证据保留，展开日志查看原因。";Append(e.ToString());folder.IsEnabled=lastOutput!=null&&Directory.Exists(lastOutput);}
        finally{running=false;scan.IsEnabled=window.IsEnabled=true;progress.IsIndeterminate=false;progress.Visibility=Visibility.Collapsed;}
    }
    [STAThread]static int Main(string[] args){
                if(args.Length>0 && args[0]=="--scan") {
            string root=args.Length>1?Path.GetFullPath(args[1]):DefaultRoot();
            string output=NewOutput(root);
            string evidence=args.Length>2?Path.GetFullPath(args[2]):null;
            return YingJiRuntime.Collector.Run(output,72,evidence,s=>Console.WriteLine(s));
        }
        AppContext.SetSwitch("Switch.System.Windows.DoNotScaleForDpiChanges",false);
        var app=new Application();app.Run(new YingJi());return 0;
    }
}
