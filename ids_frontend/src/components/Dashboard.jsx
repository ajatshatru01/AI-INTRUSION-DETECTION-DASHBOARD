import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { UploadCloud, FileText, AlertTriangle, ShieldCheck, Activity, BarChart2 } from 'lucide-react';
import { uploadCSV } from '../services/api';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = ['#EF4444', '#F59E0B', '#3B82F6', '#10B981', '#8B5CF6'];

const StatCard = ({ title, value, subtext, icon: Icon, color }) => (
    <div className="bg-[#13151b] border border-gray-800 rounded-xl p-6 flex items-start justify-between hover:border-blue-500/50 transition-all duration-300 group">
        <div>
            <p className="text-gray-400 text-sm font-medium mb-1 group-hover:text-gray-300 transition-colors">{title}</p>
            <h3 className="text-3xl font-bold text-white tracking-tight group-hover:scale-105 transition-transform origin-left">{value}</h3>
            {subtext && <p className={`text-xs mt-2 ${color} font-medium`}>{subtext}</p>}
        </div>
        <div className={`p-4 rounded-xl bg-opacity-10 ${color.replace('text-', 'bg-')} group-hover:bg-opacity-20 transition-all`}>
            <Icon size={28} className={color} />
        </div>
    </div>
);

const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
        return (
            <div className="bg-[#1a1d24] border border-gray-700 p-3 rounded-lg shadow-xl">
                <p className="text-gray-200 font-medium">{`${payload[0].name} : ${payload[0].value}`}</p>
            </div>
        );
    }
    return null;
};

export const Dashboard = () => {
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleFileChange = (e) => {
        if (e.target.files[0]) {
            setFile(e.target.files[0]);
            setError(null);
        }
    };

    const handleUpload = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const data = await uploadCSV(file);
            setResult(data);
        } catch (err) {
            setError(err.message || 'Analysis failed');
        } finally {
            setLoading(false);
        }
    };

    // Prepare chart data
    const chartData = result ? Object.entries(result.attack_distribution).map(([name, value]) => ({ name, value })) : [];

    return (
        <div className="flex h-screen bg-[#0a0b10] text-gray-100 font-sans overflow-hidden selection:bg-blue-500/30">
            <Sidebar />

            <main className="flex-1 p-8 overflow-y-auto custom-scrollbar">
                <header className="flex justify-between items-end mb-10 border-b border-gray-800 pb-6">
                    <div>
                        <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                            Traffic Analysis
                        </h1>
                        <p className="text-gray-500 text-sm mt-1">Offline Threat Detection & Forensics</p>
                    </div>
                    {result && (
                        <button
                            onClick={() => { setFile(null); setResult(null); setError(null); }}
                            className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-sm font-medium transition-all hover:shadow-lg flex items-center gap-2 border border-gray-700 hover:border-gray-600"
                        >
                            <FileText size={16} />
                            Analyze Another File
                        </button>
                    )}
                </header>

                {/* Upload Section */}
                {!result && !loading && (
                    <div className="flex flex-col items-center justify-center h-[60vh] animate-in fade-in zoom-in duration-500">
                        <div className="max-w-xl w-full">
                            <label
                                htmlFor="csv-upload"
                                className={`relative group cursor-pointer flex flex-col items-center justify-center w-full h-80 rounded-3xl border-2 border-dashed transition-all duration-300 bg-[#13151b]/50 backdrop-blur-sm
                                ${file ? 'border-blue-500/50 bg-blue-500/5' : 'border-gray-700 hover:border-blue-500/50 hover:bg-[#13151b]'}`}
                            >
                                <div className="absolute inset-0 bg-blue-500/5 rounded-3xl opacity-0 group-hover:opacity-100 transition-opacity" />
                                <input
                                    type="file"
                                    accept=".csv"
                                    onChange={handleFileChange}
                                    className="hidden"
                                    id="csv-upload"
                                />

                                <div className="z-10 flex flex-col items-center text-center p-8">
                                    <div className={`p-5 rounded-2xl mb-6 transition-all duration-300 ${file ? 'bg-blue-500/20 text-blue-400' : 'bg-gray-800 text-gray-400 group-hover:scale-110 group-hover:text-blue-400 group-hover:bg-blue-500/20'}`}>
                                        <UploadCloud size={48} />
                                    </div>
                                    <h3 className="text-2xl font-bold text-white mb-2">
                                        {file ? file.name : "Upload Capture File"}
                                    </h3>
                                    <p className="text-gray-400 max-w-xs mx-auto">
                                        {file ? "Ready to analyze" : "Drag & drop or click to upload CSV (CIC-IDS-2017 Format)"}
                                    </p>
                                </div>
                            </label>

                            {file && (
                                <button
                                    onClick={handleUpload}
                                    className="w-full mt-6 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white p-4 rounded-xl font-bold text-lg shadow-lg hover:shadow-blue-500/25 transition-all transform hover:-translate-y-1 active:scale-[0.98]"
                                >
                                    Start Analysis
                                </button>
                            )}
                        </div>
                    </div>
                )}

                {loading && (
                    <div className="flex flex-col items-center justify-center h-[60vh] space-y-6 animate-pulse">
                        <div className="relative w-24 h-24">
                            <div className="absolute inset-0 border-4 border-blue-500/30 rounded-full"></div>
                            <div className="absolute inset-0 border-4 border-t-blue-500 rounded-full animate-spin"></div>
                            <Activity className="absolute inset-0 m-auto text-blue-500" size={32} />
                        </div>
                        <div className="text-center">
                            <h3 className="text-xl font-bold text-white mb-2">Analyzing Patterns...</h3>
                            <p className="text-gray-400">Running Deep Neural Network Inference</p>
                        </div>
                    </div>
                )}

                {/* Results Section */}
                {result && (
                    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-8 duration-700">
                        {/* Stats Grid */}
                        <div className="grid grid-cols-3 gap-6">
                            <StatCard
                                title="Total Flows Processed"
                                value={result.total_rows.toLocaleString()}
                                icon={FileText}
                                color="text-gray-400"
                            />
                            <StatCard
                                title="Benign Traffic"
                                value={result.benign_count.toLocaleString()}
                                subtext={`${((result.benign_count / result.total_rows) * 100).toFixed(1)}% safe`}
                                icon={ShieldCheck}
                                color="text-emerald-400"
                            />
                            <StatCard
                                title="Threats Detected"
                                value={result.malicious_count.toLocaleString()}
                                subtext={`${((result.malicious_count / result.total_rows) * 100).toFixed(1)}% malicious`}
                                icon={AlertTriangle}
                                color="text-red-400"
                            />
                        </div>

                        {/* Distributions */}
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                            {/* Attack Types Table */}
                            <div className="lg:col-span-2 bg-[#13151b] border border-gray-800 rounded-2xl p-6 flex flex-col h-[500px]">
                                <div className="flex items-center justify-between mb-6">
                                    <h3 className="text-lg font-bold flex items-center gap-2">
                                        <div className="p-2 rounded-lg bg-red-500/10 text-red-400">
                                            <Activity size={20} />
                                        </div>
                                        Threat Log
                                    </h3>
                                    <span className="text-xs font-mono text-gray-500 bg-gray-900 px-2 py-1 rounded">
                                        TOP 100
                                    </span>
                                </div>
                                <div className="overflow-auto flex-1 pr-2 custom-scrollbar">
                                    <table className="w-full text-left text-sm">
                                        <thead className="text-gray-500 border-b border-gray-800/50 sticky top-0 bg-[#13151b] z-10">
                                            <tr>
                                                <th className="pb-4 pl-4 font-medium">Row #</th>
                                                <th className="pb-4 font-medium">Attack Signature</th>
                                                <th className="pb-4 font-medium">Confidence</th>
                                                <th className="pb-4 text-right pr-4 font-medium">Severity</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-gray-800/50">
                                            {result.attacks.length > 0 ? (
                                                result.attacks.map((attack, i) => (
                                                    <tr key={i} className="group hover:bg-white/[0.02] transition-colors">
                                                        <td className="py-3 pl-4 text-gray-500 font-mono text-xs">#{attack.row_index}</td>
                                                        <td className="py-3 font-medium text-gray-200 group-hover:text-red-300 transition-colors">
                                                            {attack.attack_type}
                                                        </td>
                                                        <td className="py-3">
                                                            <div className="flex items-center gap-2">
                                                                <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                                                    <div
                                                                        className="h-full bg-blue-500 rounded-full"
                                                                        style={{ width: `${attack.confidence * 100}%` }}
                                                                    />
                                                                </div>
                                                                <span className="text-xs text-gray-400">{(attack.confidence * 100).toFixed(0)}%</span>
                                                            </div>
                                                        </td>
                                                        <td className="py-3 text-right pr-4">
                                                            <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-2.5 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide">
                                                                Critical
                                                            </span>
                                                        </td>
                                                    </tr>
                                                ))
                                            ) : (
                                                <tr>
                                                    <td colSpan="4" className="py-12 text-center text-gray-500">
                                                        <ShieldCheck className="mx-auto mb-3 text-gray-600" size={32} />
                                                        No threats detected in this file. Great job!
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>

                            {/* Attack Distribution Chart */}
                            <div className="lg:col-span-1 bg-[#13151b] border border-gray-800 rounded-2xl p-6 flex flex-col h-[500px]">
                                <h3 className="text-lg font-bold mb-2 flex items-center gap-2">
                                    <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
                                        <BarChart2 size={20} />
                                    </div>
                                    Attack Distribution
                                </h3>

                                {Object.keys(result.attack_distribution).length > 0 ? (
                                    <div className="flex-1 min-h-0 relative">
                                        <ResponsiveContainer width="100%" height="100%">
                                            <PieChart>
                                                <Pie
                                                    data={chartData}
                                                    cx="50%"
                                                    cy="50%"
                                                    innerRadius={60}
                                                    outerRadius={80}
                                                    paddingAngle={5}
                                                    dataKey="value"
                                                    stroke="none"
                                                >
                                                    {chartData.map((entry, index) => (
                                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                                    ))}
                                                </Pie>
                                                <Tooltip content={<CustomTooltip />} />
                                                <Legend
                                                    verticalAlign="bottom"
                                                    height={36}
                                                    iconType="circle"
                                                    formatter={(value) => <span className="text-gray-400 text-xs ml-1">{value}</span>}
                                                />
                                            </PieChart>
                                        </ResponsiveContainer>

                                        {/* Center Text */}
                                        <div className="absolute inset-0 flex items-center justify-center pointer-events-none pb-8">
                                            <div className="text-center">
                                                <div className="text-2xl font-bold text-white">{result.malicious_count}</div>
                                                <div className="text-xs text-gray-500 uppercase tracking-widest">Threats</div>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
                                        No data to display
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
};
