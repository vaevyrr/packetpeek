from __future__ import annotations
import json, threading, tkinter as tk
from tkinter import filedialog, messagebox, ttk
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from packetpeek import read_pcap

class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("PacketPeek"); self.geometry("1100x680"); self.minsize(850,520); self.build()
    def build(self):
        top=ttk.Frame(self,padding=12); top.pack(fill="x")
        ttk.Label(top,text="PacketPeek",font=("Segoe UI",16,"bold")).pack(anchor="w")
        ttk.Label(top,text="Offline PCAP inspection — no packets are transmitted.").pack(anchor="w",pady=(2,8))
        row=ttk.Frame(top); row.pack(fill="x"); self.path=tk.StringVar()
        ttk.Entry(row,textvariable=self.path).pack(side="left",fill="x",expand=True)
        ttk.Button(row,text="Open PCAP",command=self.choose).pack(side="left",padx=6)
        ttk.Label(row,text="Top").pack(side="left"); self.topn=tk.StringVar(value="10"); ttk.Entry(row,textvariable=self.topn,width=6).pack(side="left",padx=5)
        self.go=ttk.Button(row,text="Inspect",command=self.run); self.go.pack(side="left")
        self.status=tk.StringVar(value="Ready"); ttk.Label(top,textvariable=self.status).pack(anchor="w",pady=(8,0))
        tabs=ttk.Notebook(self); tabs.pack(fill="both",expand=True,padx=12,pady=(0,12))
        self.summary=ttk.Treeview(tabs,columns=("metric","value"),show="headings"); self.summary.heading("metric",text="Metric"); self.summary.heading("value",text="Value"); self.summary.column("metric",width=260); self.summary.column("value",width=700)
        self.packets=ttk.Treeview(tabs,columns=("no","time","src","dst","proto","sport","dport","info","flags"),show="headings")
        for c,w in zip(("no","time","src","dst","proto","sport","dport","info","flags"),(60,220,130,130,80,70,70,250,80)): self.packets.heading(c,text=c.upper()); self.packets.column(c,width=w,anchor="w")
        tabs.add(self.summary,text="Summary"); tabs.add(self.packets,text="Packets")
        bottom=ttk.Frame(self,padding=12); bottom.pack(fill="x")
        ttk.Button(bottom,text="Export JSON",command=self.export_json).pack(side="right")
        ttk.Button(bottom,text="Export CSV",command=self.export_csv).pack(side="right",padx=6)
    def choose(self):
        p=filedialog.askopenfilename(filetypes=[("PCAP","*.pcap *.cap"),("All files","*.*")])
        if p:self.path.set(p)
    def run(self):
        p=Path(self.path.get())
        if not p.is_file(): messagebox.showerror("Inspect","Choose a PCAP."); return
        try: top=max(1,int(self.topn.get()))
        except ValueError: messagebox.showerror("Inspect","Top must be a positive integer."); return
        self.go.configure(state="disabled"); self.status.set("Reading capture...")
        def work():
            try:r=list(read_pcap(p)); err=None
            except Exception as e:r=None; err=str(e)
            self.after(0,lambda:self.finish(r,err,top))
        threading.Thread(target=work,daemon=True).start()
    def finish(self,packets,err,top):
        self.go.configure(state="normal")
        if err:self.status.set("Failed"); messagebox.showerror("PCAP error",err); return
        for t in (self.summary,self.packets):
            for i in t.get_children():t.delete(i)
        protocols=Counter(p.protocol for p in packets); conv=Counter()
        for p in packets:
            if p.source and p.destination:
                a,b=sorted((p.source,p.destination)); conv[(a,b,p.protocol)]+=1
        self.summary.insert("", "end",values=("Packets",len(packets)))
        for k,v in protocols.most_common(): self.summary.insert("", "end",values=(f"Protocol: {k}",v))
        for (a,b,proto),n in conv.most_common(top): self.summary.insert("", "end",values=(f"{a} <-> {b} ({proto})",n))
        for p in packets:self.packets.insert("", "end",values=(p.number,p.timestamp,p.source,p.destination,p.protocol,p.source_port or "",p.destination_port or "",p.info,p.flags))
        self.last=packets; self.status.set(f"Complete • {len(packets)} packets")
    def export_json(self):
        if not hasattr(self,"last"):return
        p=filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json")])
        if p:Path(p).write_text(json.dumps([asdict(x) for x in self.last],indent=2),encoding="utf-8")
    def export_csv(self):
        if not hasattr(self,"last"):return
        import csv
        p=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")])
        if p:
            rows=[asdict(x) for x in self.last]
            with open(p,"w",newline="",encoding="utf-8") as f:
                w=csv.DictWriter(f,fieldnames=rows[0].keys() if rows else ["number"]);w.writeheader();w.writerows(rows)

if __name__=="__main__":App().mainloop()
