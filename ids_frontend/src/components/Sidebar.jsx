import React from 'react';
import { LayoutDashboard, History, Settings, Shield } from 'lucide-react';

export const Sidebar = () => {
    const navItems = [
        { icon: LayoutDashboard, label: 'Overview', active: true },
    ];

    return (
        <div className="w-64 bg-dark h-screen border-r border-gray-800 flex flex-col p-4">
            <div className="flex items-center gap-3 mb-8 px-2">
                <Shield className="text-cyan" size={32} />
                <div>
                    <h1 className="text-xl font-bold tracking-wider">NETGUARD</h1>
                    <div className="text-xs text-dim">IDS SYSTEM v1.0</div>
                </div>
            </div>

            <nav className="space-y-2">
                {navItems.map((item, idx) => (
                    <button
                        key={idx}
                        className={`w-full flex items-center gap-3 px-4 py-3 rounded text-sm font-medium transition-colors
                            ${item.active
                                ? 'bg-blue-600/10 text-cyan border-l-2 border-cyan'
                                : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                            }`}
                    >
                        <item.icon size={18} />
                        {item.label}
                    </button>
                ))}
            </nav>

            <div className="mt-auto">
                <div className="bg-gray-900 rounded p-3 text-xs text-dim">
                    <div>Status: <span className="text-green">Online</span></div>
                    <div className="mt-1">Worker: active</div>
                </div>
            </div>
        </div>
    );
};
