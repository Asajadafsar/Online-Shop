
import * as React from "react";
import { Title } from 'react-admin';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,ResponsiveContainer } from 'recharts';
interface DashboardInfo {
    "weekly-sales": number;
    "weekly-payments": number;
    "total-revenue": number;
}
const data = [
    { name: 'Item 1', value: 400 },
    { name: 'Item 2', value: 300 },
    { name: 'Item 3', value: 200 },
  ];
  

const Dashboard = () => {
    const [dashboardInfo, setDashboardInfo] = React.useState<DashboardInfo | null>(null);
    const [dashboardInfo2, setDashboardInfo2] = React.useState<any>(null);
     const chartData = dashboardInfo ? [
        { name: 'Weekly Sales', value: dashboardInfo["weekly-sales"] },
        { name: 'Weekly Payments', value: dashboardInfo["weekly-payments"] },
        { name: 'Total Revenue', value: dashboardInfo["total-revenue"] }
    ] : [];
    React.useEffect(() => {
        const fetchData = async () => {
            const token = localStorage.getItem('token');
            if (!token) {
                console.error('Token not found in localStorage!');
                return;
            }

            try {
                const response = await fetch('http://localhost:5000/KPIs', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    setDashboardInfo(data);
                } else {
                    console.error('Failed to fetch dashboard info:', response.statusText);
                }
            } catch (error) {
                console.error('Error fetching dashboard info:', error);
            }
        };
        const fetchData2 = async () => {
            const token = localStorage.getItem('token');
            if (!token) {
                console.error('Token not found in localStorage!');
                return;
            }

            try {
                const response = await fetch('http://localhost:5000/trending_products', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    setDashboardInfo2(data);
                } else {
                    console.error('Failed to fetch dashboard info:', response.statusText);
                }
            } catch (error) {
                console.error('Error fetching dashboard info:', error);
            }
        };




        fetchData();
        fetchData2();
    }, []);

    if (!dashboardInfo) return null;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center'}}>
            <Typography variant="h3" sx={{marginBottom:8,marginTop:5}} gutterBottom>Welcome to Admin Panel</Typography>
            <ResponsiveContainer width="100%" height={300}>
            <BarChart
                data={dashboardInfo2}
                margin={{
                    top: 20, right: 30, left: 20, bottom: 5,
                }}
            >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="total_quantity" fill="#000" />
            </BarChart>
        </ResponsiveContainer>
        <br></br>
        <br></br>
        <br></br>
            <BarChart width={600} height={300} data={chartData}>
    <CartesianGrid strokeDasharray="3 3" />
    <XAxis dataKey="name" />
    <YAxis />
    <Tooltip />
    <Legend />
    <Bar dataKey="value" fill="#8884d8" />
  </BarChart>
        </div>
    );
};

export default Dashboard;
