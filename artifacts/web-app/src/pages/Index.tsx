import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import FilterBar from "@/components/FilterBar";
import SeverityCards from "@/components/SeverityCards";
import DonutChart from "@/components/DonutChart";
import ReviewStatusCard from "@/components/ReviewStatusCard";
import ScannedAssetsTable from "@/components/ScannedAssetsTable";

const Index = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const { data: chartData = [] } = useQuery({
    queryKey: ["chart_data"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("chart_data")
        .select("*")
        .order("sort_order", { ascending: true });
      if (error) throw error;
      return data;
    },
  });

  // Group chart data by chart_key, preserving insertion order so the
  // dashboard mirrors whatever donut definitions exist in the chart_data
  // table without us having to hardcode keys here.
  const groupedCharts = chartData.reduce((acc, item) => {
    if (!acc[item.chart_key]) {
      acc[item.chart_key] = { title: item.chart_title, data: [] };
    }
    acc[item.chart_key].data.push({
      name: item.segment_name,
      value: item.segment_value,
      color: item.segment_color,
    });
    return acc;
  }, {} as Record<string, { title: string; data: { name: string; value: number; color: string }[] }>);

  const chartList = Object.values(groupedCharts);

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        activePage="dashboard"
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <FilterBar />
          <SeverityCards />
          {chartList.length > 0 && (
            <div className="grid grid-cols-2 gap-4">
              {chartList.map((chart, i) => (
                <DonutChart key={i} title={chart.title} data={chart.data} />
              ))}
              {chartList.length % 2 === 1 && <ReviewStatusCard />}
            </div>
          )}
          {chartList.length === 0 && (
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-card border border-border rounded-lg p-5 text-sm text-muted-foreground">
                No chart segments configured. Add rows to the <code>chart_data</code> table to populate this dashboard.
              </div>
              <ReviewStatusCard />
            </div>
          )}
          {chartList.length > 0 && chartList.length % 2 === 0 && (
            <div className="grid grid-cols-1 gap-4">
              <ReviewStatusCard />
            </div>
          )}
          <ScannedAssetsTable />
        </main>
      </div>
    </div>
  );
};

export default Index;
