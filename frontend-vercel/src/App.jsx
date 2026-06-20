import { useState, useCallback, useRef } from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";

// ── Color palette ──────────────────────────────────────────────────────────────
const C = {
  bg:       "#0a0e17",
  surface:  "#111827",
  card:     "#161d2e",
  border:   "#1e2d45",
  accent:   "#00d4ff",
  accent2:  "#7c3aed",
  red:      "#ef4444",
  green:    "#22c55e",
  yellow:   "#f59e0b",
  text:     "#e2e8f0",
  muted:    "#64748b",
};

const APP_COLORS = [
  "#00d4ff","#7c3aed","#22c55e","#f59e0b","#ef4444",
  "#ec4899","#06b6d4","#84cc16","#f97316","#a78bfa",
  "#34d399","#fbbf24","#60a5fa","#fb7185","#4ade80",
];

const KNOWN_APPS = [
  "YOUTUBE","FACEBOOK","NETFLIX","INSTAGRAM","TIKTOK",
  "WHATSAPP","TELEGRAM","SPOTIFY","ZOOM","DISCORD",
  "TWITTER","GITHUB","AMAZON","GOOGLE","MICROSOFT",
  "CLOUDFLARE","TIKTOK","HTTP","HTTPS","DNS",
];

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

// ── Helpers ───────────────────────────────────────────────────────────────────
const fmt = (n) => n >= 1_000_000 ? (n/1_000_000).toFixed(1)+"M"
                 : n >= 1_000     ? (n/1_000).toFixed(1)+"K"
                 : String(n);

const fmtBytes = (b) => b >= 1e6 ? (b/1e6).toFixed(2)+" MB"
                       : b >= 1e3 ? (b/1e3).toFixed(1)+" KB"
                       : b+" B";

// ── Stat Card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color="#00d4ff", icon }) {
  return (
    <div style={{
      background: C.card, border:`1px solid ${C.border}`,
      borderRadius:12, padding:"20px 24px",
      borderLeft:`3px solid ${color}`,
    }}>
      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
        <span style={{fontSize:18}}>{icon}</span>
        <span style={{color:C.muted,fontSize:12,letterSpacing:1,textTransform:"uppercase"}}>{label}</span>
      </div>
      <div style={{color:C.text,fontSize:28,fontWeight:700,fontFamily:"monospace"}}>{value}</div>
      {sub && <div style={{color:C.muted,fontSize:12,marginTop:4}}>{sub}</div>}
    </div>
  );
}

// ── Drop Zone ─────────────────────────────────────────────────────────────────
function DropZone({ onFile, loading }) {
  const [drag, setDrag] = useState(false);
  const ref = useRef();

  const handle = (f) => { if (f && f.name.endsWith(".pcap")) onFile(f); };

  return (
    <div
      onDragOver={e=>{e.preventDefault();setDrag(true);}}
      onDragLeave={()=>setDrag(false)}
      onDrop={e=>{e.preventDefault();setDrag(false);handle(e.dataTransfer.files[0]);}}
      onClick={()=>!loading && ref.current.click()}
      style={{
        border:`2px dashed ${drag ? C.accent : C.border}`,
        borderRadius:16, padding:"48px 24px",
        textAlign:"center", cursor: loading ? "not-allowed" : "pointer",
        background: drag ? "#00d4ff0a" : C.card,
        transition:"all .2s",
      }}
    >
      <input ref={ref} type="file" accept=".pcap" style={{display:"none"}}
        onChange={e=>handle(e.target.files[0])} />
      <div style={{fontSize:48,marginBottom:12}}>
        {loading ? "⚙️" : "📦"}
      </div>
      <div style={{color:C.text,fontSize:18,fontWeight:600,marginBottom:6}}>
        {loading ? "Analyzing packets…" : "Drop your .pcap file here"}
      </div>
      <div style={{color:C.muted,fontSize:14}}>
        {loading ? "Running DPI engine, please wait" : "or click to browse • max 50 MB"}
      </div>
      {loading && (
        <div style={{marginTop:20}}>
          <div style={{
            height:4,background:C.border,borderRadius:4,overflow:"hidden",maxWidth:320,margin:"0 auto"
          }}>
            <div style={{
              height:"100%",background:`linear-gradient(90deg,${C.accent},${C.accent2})`,
              animation:"slide 1.5s infinite",borderRadius:4,
            }}/>
          </div>
        </div>
      )}
    </div>
  );
}

// ── App Pill ──────────────────────────────────────────────────────────────────
function AppPill({ name, selected, onClick }) {
  return (
    <button onClick={onClick} style={{
      padding:"6px 14px", borderRadius:20, fontSize:12, fontWeight:600,
      cursor:"pointer", transition:"all .15s",
      background: selected ? C.red : C.surface,
      color: selected ? "#fff" : C.muted,
      border: `1px solid ${selected ? C.red : C.border}`,
    }}>
      {selected ? "🚫 " : ""}{name}
    </button>
  );
}

// ── Packet Table ──────────────────────────────────────────────────────────────
function PacketTable({ packets }) {
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(0);
  const PAGE = 20;

  const filtered = packets.filter(p =>
    !filter ||
    p.src.includes(filter) || p.dst.includes(filter) ||
    p.app.toLowerCase().includes(filter.toLowerCase()) ||
    p.sni.toLowerCase().includes(filter.toLowerCase())
  );
  const total_pages = Math.ceil(filtered.length / PAGE);
  const slice = filtered.slice(page * PAGE, (page+1) * PAGE);

  const colStyle = (w) => ({
    padding:"10px 12px", textAlign:"left",
    color:C.muted, fontSize:11, fontWeight:700,
    letterSpacing:.8, textTransform:"uppercase",
    borderBottom:`1px solid ${C.border}`, width:w,
  });

  const cellStyle = (extra={}) => ({
    padding:"9px 12px", fontSize:12, color:C.text,
    borderBottom:`1px solid ${C.border}0a`,
    fontFamily:"monospace", ...extra,
  });

  return (
    <div>
      <div style={{display:"flex",gap:12,marginBottom:16,alignItems:"center"}}>
        <input
          placeholder="Filter by IP, app, domain…"
          value={filter}
          onChange={e=>{setFilter(e.target.value);setPage(0);}}
          style={{
            flex:1, padding:"10px 14px", borderRadius:8,
            background:C.surface, border:`1px solid ${C.border}`,
            color:C.text, fontSize:13, outline:"none",
          }}
        />
        <span style={{color:C.muted,fontSize:12}}>{filtered.length} packets</span>
      </div>

      <div style={{overflowX:"auto",borderRadius:10,border:`1px solid ${C.border}`}}>
        <table style={{width:"100%",borderCollapse:"collapse",minWidth:800}}>
          <thead>
            <tr style={{background:C.surface}}>
              <th style={colStyle(40)}>#</th>
              <th style={colStyle(70)}>Time</th>
              <th style={colStyle(160)}>Source</th>
              <th style={colStyle(160)}>Destination</th>
              <th style={colStyle(60)}>Proto</th>
              <th style={colStyle(100)}>App</th>
              <th style={colStyle(180)}>Domain / SNI</th>
              <th style={colStyle(70)}>Size</th>
              <th style={colStyle(70)}>Status</th>
            </tr>
          </thead>
          <tbody>
            {slice.map((p,i) => (
              <tr key={i} style={{
                background: p.blocked ? "#ef44440a" : (i%2===0 ? C.card : C.surface),
              }}>
                <td style={cellStyle({color:C.muted})}>{p.num}</td>
                <td style={cellStyle({color:C.muted,fontSize:11})}>{p.time}</td>
                <td style={cellStyle()}>{p.src}</td>
                <td style={cellStyle()}>{p.dst}</td>
                <td style={cellStyle()}>
                  <span style={{
                    padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:700,
                    background: p.proto==="TCP" ? "#00d4ff22" : "#7c3aed22",
                    color: p.proto==="TCP" ? C.accent : C.accent2,
                  }}>{p.proto}</span>
                </td>
                <td style={cellStyle({color:C.yellow,fontSize:11})}>{p.app}</td>
                <td style={cellStyle({color:C.muted,maxWidth:180,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"})}>
                  {p.sni || "—"}
                </td>
                <td style={cellStyle({color:C.muted})}>{p.size}B</td>
                <td style={cellStyle()}>
                  <span style={{
                    padding:"2px 8px",borderRadius:4,fontSize:10,fontWeight:700,
                    background: p.blocked ? "#ef444422" : "#22c55e22",
                    color: p.blocked ? C.red : C.green,
                  }}>
                    {p.blocked ? "BLOCKED" : "OK"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {total_pages > 1 && (
        <div style={{display:"flex",gap:8,marginTop:12,justifyContent:"center"}}>
          {[...Array(Math.min(total_pages,10))].map((_,i)=>(
            <button key={i} onClick={()=>setPage(i)} style={{
              width:32, height:32, borderRadius:6,
              background: page===i ? C.accent : C.surface,
              color: page===i ? C.bg : C.muted,
              border:`1px solid ${C.border}`,
              cursor:"pointer",fontSize:12,fontWeight:600,
            }}>{i+1}</button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [file, setFile]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [data, setData]       = useState(null);
  const [error, setError]     = useState("");
  const [blocked, setBlocked] = useState(new Set());
  const [tab, setTab]         = useState("overview");

  const toggleApp = (app) => {
    setBlocked(prev => {
      const s = new Set(prev);
      s.has(app) ? s.delete(app) : s.add(app);
      return s;
    });
  };

  const analyze = useCallback(async (f) => {
    setFile(f);
    setLoading(true);
    setError("");
    setData(null);

    const fd = new FormData();
    fd.append("file", f);
    fd.append("block_apps", [...blocked].join(","));

    try {
      const res = await fetch(`${API}/analyze`, { method:"POST", body:fd });
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail || "Analysis failed");
      setData(json);
      setTab("overview");
    } catch(e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [blocked]);

  const downloadOutput = () => {
    if (data?.job_id) window.open(`${API}/download/${data.job_id}`);
  };

  const TABS = ["overview","packets","flows","domains"];

  return (
    <div style={{
      minHeight:"100vh", background:C.bg, color:C.text,
      fontFamily:"'Inter',system-ui,sans-serif",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width:6px; height:6px; }
        ::-webkit-scrollbar-track { background:${C.bg}; }
        ::-webkit-scrollbar-thumb { background:${C.border}; border-radius:3px; }
        @keyframes slide {
          0%   { width:0%; margin-left:0; }
          50%  { width:60%; margin-left:20%; }
          100% { width:0%; margin-left:100%; }
        }
      `}</style>

      {/* Header */}
      <div style={{
        borderBottom:`1px solid ${C.border}`,
        background:`${C.surface}cc`,
        backdropFilter:"blur(12px)",
        position:"sticky",top:0,zIndex:100,
      }}>
        <div style={{maxWidth:1280,margin:"0 auto",padding:"16px 24px",
                     display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            <div style={{
              width:36,height:36,borderRadius:8,
              background:`linear-gradient(135deg,${C.accent},${C.accent2})`,
              display:"flex",alignItems:"center",justifyContent:"center",
              fontSize:18,
            }}>🔍</div>
            <div>
              <div style={{fontWeight:700,fontSize:17,letterSpacing:.3}}>DPI Engine</div>
              <div style={{color:C.muted,fontSize:11}}>Deep Packet Inspection</div>
            </div>
          </div>
          {data && (
            <button onClick={downloadOutput} style={{
              padding:"8px 18px",borderRadius:8,
              background:`linear-gradient(135deg,${C.accent},${C.accent2})`,
              color:"#fff",border:"none",cursor:"pointer",
              fontSize:13,fontWeight:600,
            }}>
              ⬇ Download Filtered PCAP
            </button>
          )}
        </div>
      </div>

      <div style={{maxWidth:1280,margin:"0 auto",padding:"32px 24px"}}>

        {/* Upload + Block rules */}
        <div style={{
          display:"grid",
          gridTemplateColumns: data ? "1fr" : "1fr 340px",
          gap:24,marginBottom:32,
        }}>
          <div>
            <DropZone onFile={analyze} loading={loading} />
            {error && (
              <div style={{
                marginTop:12,padding:"12px 16px",borderRadius:8,
                background:"#ef444422",border:`1px solid ${C.red}`,
                color:C.red,fontSize:13,
              }}>⚠ {error}</div>
            )}
          </div>

          {!data && (
            <div style={{
              background:C.card,border:`1px solid ${C.border}`,
              borderRadius:12,padding:20,
            }}>
              <div style={{
                color:C.muted,fontSize:11,letterSpacing:1,
                textTransform:"uppercase",fontWeight:700,marginBottom:14,
              }}>🚫 Block Apps Before Analyzing</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                {KNOWN_APPS.map(a=>(
                  <AppPill key={a} name={a}
                    selected={blocked.has(a)}
                    onClick={()=>toggleApp(a)} />
                ))}
              </div>
              {blocked.size > 0 && (
                <div style={{
                  marginTop:14,padding:"8px 12px",borderRadius:8,
                  background:"#ef444411",border:`1px solid ${C.red}22`,
                  color:C.red,fontSize:12,
                }}>
                  {blocked.size} app{blocked.size>1?"s":""} will be blocked
                </div>
              )}
            </div>
          )}
        </div>

        {/* Results */}
        {data && (
          <div>
            {/* Re-analyze / change rules bar */}
            <div style={{
              background:C.card,border:`1px solid ${C.border}`,
              borderRadius:12,padding:"16px 20px",marginBottom:24,
              display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:12,
            }}>
              <div style={{display:"flex",alignItems:"center",gap:12,flexWrap:"wrap"}}>
                <span style={{color:C.muted,fontSize:13}}>📄 {data.filename}</span>
                <span style={{color:C.muted,fontSize:13}}>•</span>
                <span style={{color:C.muted,fontSize:13}}>{fmtBytes(data.file_size)}</span>
                {data.blocked_apps?.length > 0 && (
                  <>
                    <span style={{color:C.muted,fontSize:13}}>•</span>
                    <span style={{color:C.red,fontSize:12}}>
                      🚫 Blocking: {data.blocked_apps.join(", ")}
                    </span>
                  </>
                )}
              </div>
              <button
                onClick={()=>{ setData(null); setFile(null); }}
                style={{
                  padding:"7px 16px",borderRadius:8,background:"transparent",
                  color:C.accent,border:`1px solid ${C.accent}44`,
                  cursor:"pointer",fontSize:13,fontWeight:600,
                }}>
                + Analyze Another File
              </button>
            </div>

            {/* Stat cards */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:16,marginBottom:28}}>
              <StatCard icon="📦" label="Total Packets" color={C.accent}
                value={fmt(data.summary.total_packets)} />
              <StatCard icon="✅" label="Forwarded" color={C.green}
                value={fmt(data.summary.forwarded)}
                sub={`${((data.summary.forwarded/data.summary.total_packets)*100).toFixed(1)}%`} />
              <StatCard icon="🚫" label="Dropped" color={C.red}
                value={fmt(data.summary.dropped)}
                sub={`${((data.summary.dropped/data.summary.total_packets)*100).toFixed(1)}%`} />
              <StatCard icon="🔗" label="Unique Flows" color={C.accent2}
                value={fmt(data.summary.total_flows)} />
              <StatCard icon="📡" label="TCP Packets" color={C.yellow}
                value={fmt(data.summary.tcp_packets)} />
              <StatCard icon="📻" label="UDP Packets" color="#06b6d4"
                value={fmt(data.summary.udp_packets)} />
            </div>

            {/* Tabs */}
            <div style={{
              display:"flex",gap:4,marginBottom:24,
              borderBottom:`1px solid ${C.border}`,paddingBottom:0,
            }}>
              {TABS.map(t=>(
                <button key={t} onClick={()=>setTab(t)} style={{
                  padding:"10px 20px",borderRadius:"8px 8px 0 0",
                  background: tab===t ? C.card : "transparent",
                  color: tab===t ? C.text : C.muted,
                  border: tab===t ? `1px solid ${C.border}` : "1px solid transparent",
                  borderBottom: tab===t ? `1px solid ${C.card}` : "none",
                  cursor:"pointer",fontSize:13,fontWeight:600,
                  textTransform:"capitalize",marginBottom:-1,
                }}>
                  {t==="overview" ? "📊 " : t==="packets" ? "📋 " : t==="flows" ? "🔗 " : "🌐 "}
                  {t}
                </button>
              ))}
            </div>

            {/* Overview Tab */}
            {tab==="overview" && (
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:24}}>
                {/* Pie chart */}
                <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:24}}>
                  <div style={{fontWeight:700,marginBottom:16,fontSize:15}}>
                    App Distribution
                  </div>
                  <ResponsiveContainer width="100%" height={280}>
                    <PieChart>
                      <Pie
                        data={data.app_distribution.slice(0,10)}
                        dataKey="count"
                        nameKey="app"
                        cx="45%"cy="50%"
                        innerRadius={60}outerRadius={100}
                        paddingAngle={2}
                      >
                        {data.app_distribution.slice(0,10).map((_,i)=>(
                          <Cell key={i} fill={APP_COLORS[i%APP_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12}}
                        formatter={(v,n)=>[fmt(v)+" packets",n]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  {/* Legend */}
                  <div style={{display:"flex",flexWrap:"wrap",gap:"6px 16px",marginTop:12}}>
                    {data.app_distribution.slice(0,10).map((d,i)=>(
                      <div key={i} style={{display:"flex",alignItems:"center",gap:6,fontSize:12}}>
                        <div style={{width:10,height:10,borderRadius:2,background:APP_COLORS[i%APP_COLORS.length]}}/>
                        <span style={{color:C.muted}}>{d.app}</span>
                        <span style={{color:C.text,fontWeight:600}}>{d.percent}%</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Bar chart */}
                <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:24}}>
                  <div style={{fontWeight:700,marginBottom:16,fontSize:15}}>
                    Top Apps by Packets
                  </div>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart
                      data={data.app_distribution.slice(0,8)}
                      layout="vertical"
                      margin={{left:10,right:20,top:0,bottom:0}}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke={C.border} horizontal={false}/>
                      <XAxis type="number" tick={{fill:C.muted,fontSize:11}} axisLine={false} tickLine={false}/>
                      <YAxis dataKey="app" type="category" tick={{fill:C.muted,fontSize:11}} width={90} axisLine={false} tickLine={false}/>
                      <Tooltip
                        contentStyle={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12}}
                      />
                      <Bar dataKey="count" name="Packets" radius={[0,4,4,0]}>
                        {data.app_distribution.slice(0,8).map((_,i)=>(
                          <Cell key={i} fill={APP_COLORS[i%APP_COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Packets Tab */}
            {tab==="packets" && (
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:24}}>
                <div style={{fontWeight:700,marginBottom:16,fontSize:15}}>
                  Packet Inspector {data.packets?.length >= 500 && <span style={{color:C.muted,fontSize:12,fontWeight:400}}>(showing first 500)</span>}
                </div>
                <PacketTable packets={data.packets || []} />
              </div>
            )}

            {/* Flows Tab */}
            {tab==="flows" && (
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:24}}>
                <div style={{fontWeight:700,marginBottom:16,fontSize:15}}>Top Flows by Bytes</div>
                <div style={{overflowX:"auto"}}>
                  <table style={{width:"100%",borderCollapse:"collapse",minWidth:700}}>
                    <thead>
                      <tr style={{background:C.surface}}>
                        {["Source","Destination","Proto","App","Domain","Packets","Bytes","Status"].map(h=>(
                          <th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,
                            fontSize:11,fontWeight:700,letterSpacing:.8,textTransform:"uppercase",
                            borderBottom:`1px solid ${C.border}`}}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.top_flows?.map((f,i)=>(
                        <tr key={i} style={{background:f.blocked?"#ef44440a":i%2===0?C.card:C.surface}}>
                          <td style={{padding:"9px 14px",fontSize:12,fontFamily:"monospace",color:C.text,borderBottom:`1px solid ${C.border}0a`}}>{f.src}</td>
                          <td style={{padding:"9px 14px",fontSize:12,fontFamily:"monospace",color:C.text,borderBottom:`1px solid ${C.border}0a`}}>{f.dst}</td>
                          <td style={{padding:"9px 14px",fontSize:12,borderBottom:`1px solid ${C.border}0a`}}>
                            <span style={{padding:"2px 8px",borderRadius:4,fontSize:10,fontWeight:700,
                              background:f.proto==="TCP"?"#00d4ff22":"#7c3aed22",
                              color:f.proto==="TCP"?C.accent:C.accent2}}>{f.proto}</span>
                          </td>
                          <td style={{padding:"9px 14px",fontSize:12,color:C.yellow,borderBottom:`1px solid ${C.border}0a`}}>{f.app}</td>
                          <td style={{padding:"9px 14px",fontSize:12,color:C.muted,maxWidth:180,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",borderBottom:`1px solid ${C.border}0a`}}>{f.sni||"—"}</td>
                          <td style={{padding:"9px 14px",fontSize:12,fontFamily:"monospace",color:C.text,borderBottom:`1px solid ${C.border}0a`}}>{fmt(f.packets)}</td>
                          <td style={{padding:"9px 14px",fontSize:12,fontFamily:"monospace",color:C.text,borderBottom:`1px solid ${C.border}0a`}}>{fmtBytes(f.bytes)}</td>
                          <td style={{padding:"9px 14px",borderBottom:`1px solid ${C.border}0a`}}>
                            <span style={{padding:"2px 8px",borderRadius:4,fontSize:10,fontWeight:700,
                              background:f.blocked?"#ef444422":"#22c55e22",
                              color:f.blocked?C.red:C.green}}>
                              {f.blocked?"BLOCKED":"OK"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Domains Tab */}
            {tab==="domains" && (
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:24}}>
                <div style={{fontWeight:700,marginBottom:16,fontSize:15}}>
                  Detected Domains / SNI Hostnames
                  <span style={{color:C.muted,fontSize:13,fontWeight:400,marginLeft:10}}>
                    ({data.detected_domains?.length || 0} unique)
                  </span>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:10}}>
                  {data.detected_domains?.map((d,i)=>(
                    <div key={i} style={{
                      background:C.surface,border:`1px solid ${C.border}`,
                      borderRadius:8,padding:"12px 16px",
                      display:"flex",alignItems:"center",justifyContent:"space-between",
                    }}>
                      <div>
                        <div style={{fontSize:13,color:C.text,fontFamily:"monospace",marginBottom:4}}>
                          {d.domain}
                        </div>
                        <div style={{fontSize:11,color:C.yellow}}>{d.app}</div>
                      </div>
                      <div style={{
                        width:8,height:8,borderRadius:"50%",flexShrink:0,
                        background:APP_COLORS[i%APP_COLORS.length],
                      }}/>
                    </div>
                  ))}
                  {(!data.detected_domains || data.detected_domains.length===0) && (
                    <div style={{color:C.muted,fontSize:14,gridColumn:"1/-1"}}>
                      No SNI/Host domains detected in this capture.
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Landing state — feature cards */}
        {!data && !loading && (
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))",gap:16,marginTop:8}}>
            {[
              {icon:"🔒",title:"TLS/SNI Detection",desc:"Identifies HTTPS destinations by reading the TLS Client Hello SNI field"},
              {icon:"⚡",title:"Multi-threaded Engine",desc:"Parallel Load Balancer + Fast Path threads for high-throughput processing"},
              {icon:"🚫",title:"App-level Blocking",desc:"Block YouTube, Netflix, TikTok and 20+ apps with one click"},
              {icon:"📊",title:"Flow Analytics",desc:"Per-connection stats: bytes, packets, protocol, detected app"},
            ].map((f,i)=>(
              <div key={i} style={{
                background:C.card,border:`1px solid ${C.border}`,
                borderRadius:12,padding:"20px 20px",
              }}>
                <div style={{fontSize:28,marginBottom:10}}>{f.icon}</div>
                <div style={{fontWeight:700,fontSize:14,marginBottom:6}}>{f.title}</div>
                <div style={{color:C.muted,fontSize:13,lineHeight:1.6}}>{f.desc}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
