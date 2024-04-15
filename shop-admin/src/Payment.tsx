import * as React from 'react';
import {
    List,
    Datagrid,
    TextField,
    TextInput,
    SearchInput,
    TopToolbar,
    CreateButton,
    Pagination,
    FilterButton,
    Create, 
    SimpleForm, 
    FilterForm,
     required,
     NumberField ,

} from 'react-admin';
import { DateField } from 'react-admin';
import { Stack } from '@mui/material';



const CustomerFilters = [
    <SearchInput source="payment_method" alwaysOn />,
    <TextInput label="payment_method" source="payment_method"  resettable />,
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={CustomerFilters} />
        <div>
            <FilterButton filters={CustomerFilters} />
           
        </div>
    </Stack>
)
export const PaymentList = () => (
    <List>
    <ListToolbar />
        <Datagrid rowClick="edit">
        <TextField source="id" label="ID" />
            <TextField source="order_id" label="Order ID" />
            <TextField source="payment_method" label="Payment Method" />
            <NumberField source="amount" label="Amount" options={{ style: 'currency', currency: 'USD' }} />
            <DateField source="payment_date" label="Payment Date" options={{ format: 'YYYY-MM-DD' }} />
                    </Datagrid>
    </List>
);

export default PaymentList;