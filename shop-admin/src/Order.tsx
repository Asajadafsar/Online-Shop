import * as React from 'react';
import { useRef } from 'react';
import {
    List,
    Datagrid,
    TextField,
    NumberField,
    TextInput,
    SearchInput,
    FilterButton,
    TopToolbar,
    CreateButton,
    useListContext,
    Pagination,
    FilterForm,
    ImageField,
    Show,
    DateField,
    SimpleShowLayout,
    SimpleForm,
    NumberInput,
    DateInput,
    Edit,
    required,
    ArrayField
} from 'react-admin';
import { Button, useNotify, useRefresh, useRedirect } from 'react-admin';
import { jsPDF } from "jspdf";
import html2canvas from "html2canvas";
import axios from 'axios';

import { Stack } from '@mui/material';
import { SelectInput } from 'react-admin';
const OrderFilters = [
    // <SearchInput source="user_id" alwaysOn />,
    // <DateInput label="Order Date" source="order_date" />,
    <SelectInput label="Status" source="status" choices={[
        { id: 'sent', name: 'Sent' },
        { id: 'pending', name: 'Pending' },
        { id: 'returned', name: 'returned' },
        { id: 'return requested', name: 'return requested' },
        { id: 'delivered', name: 'delivered' },
        { id: 'imperfect', name: 'imperfect' },
        { id: 'canceled', name: 'canceled' },

    ]} />,
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={OrderFilters} />
        <div>
            <FilterButton filters={OrderFilters} />
        </div>
    </Stack>
);

export const OrderEdit = (props: any) => (
    <Edit {...props} undoable={false}>
        <SimpleForm>
            <TextInput disabled source="id" label="ID" />
            <TextInput disabled source="user_id" label="User ID" />
            <TextInput source="total_amount" label="Total Amount" />
            <SelectInput source="status" label="Status" choices={[
                { id: 'sent', name: 'Sent' },
                { id: 'pending', name: 'Pending' },
                { id: 'returned', name: 'Returned' },
                { id: 'return_requested', name: 'Return Requested' },
                { id: 'delivered', name: 'Delivered' },
                { id: 'imperfect', name: 'Imperfect' },
                { id: 'canceled', name: 'canceled' },
            ]} />
            <DateInput disabled source="order_date" label="Order Date" />
        </SimpleForm>
    </Edit>
);

export const OrderShow = (props: any) => {
    const notify = useNotify();
    const refresh = useRefresh();
    const redirect = useRedirect();
   

    const printRef = useRef(); // ایجاد ref

    const handleGeneratePDF = async () => {
        const input = printRef.current; // دسترسی به عنصر از طریق ref

        if (input) {
            html2canvas(input)
                .then((canvas) => {
                    const imgData = canvas.toDataURL('image/png');
                    const pdf = new jsPDF({
                        orientation: "portrait",
                        unit: "px",
                        format: [canvas.width, canvas.height]
                    });
                    pdf.addImage(imgData, 'PNG', 0, 0, canvas.width, canvas.height);
                    pdf.save("order-details.pdf");
                })
                .catch(error => {
                    console.error('Could not generate PDF', error);
                    notify('Failed to generate PDF', 'warning');
                });
        }
    };;

    
    return (
        <div ref={printRef}>
        <Show {...props} ref={printRef} >
            <SimpleShowLayout>
                <TextField source="id" label="Order ID" />
                <TextField source="user_id" label="User ID" />
                <DateField source="order_date" label="Order Date" />
                <TextField source="total_amount" label="Total Amount" />
                <TextField source="status" label="Status" />

                <ArrayField source="details" label="Order Details">
                    <Datagrid bulkActionButtons={false} rowClick="show">
                        <TextField source="order_detail_id" label="Detail ID" />
                        <TextField source="product_id" label="Product ID" />
                        <TextField source="product_name" label="Product Name" />
                        <ImageField source="image" label="Product Image" />
                        <TextField source="quantity" label="Quantity" />
                        <TextField source="unit_price" label="Unit Price" />
                        <TextField source="total_price" label="Total Price" />
                    </Datagrid>
                </ArrayField>
            </SimpleShowLayout>
            <Button label="Generate PDF" onClick={handleGeneratePDF} />
        </Show>
        </div>
    );
};


export const OrderList = (props: any) => (
    <List>
        <ListToolbar />
        <Datagrid rowClick="edit">
            <TextField source="id" label="Order ID" />
            <TextField source="user_id" label="User ID" />
            <TextField source="total_amount" label="Total Amount" />
            <NumberField source="status" label="Status" />
            <DateField source="order_date" label="Order Date" />
        </Datagrid>
    </List>
);
