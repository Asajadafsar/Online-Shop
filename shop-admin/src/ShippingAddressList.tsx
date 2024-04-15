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

} from 'react-admin';
import { Stack } from '@mui/material';



const CustomerFilters = [
    <SearchInput source="recipient_name" alwaysOn />,
    <TextInput label="city" source="city"  resettable />,
    <TextInput label="country" source="country"  resettable />,
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={CustomerFilters} />
        <div>
            <FilterButton filters={CustomerFilters} />
           
        </div>
    </Stack>
)
export const Adresslist = () => (
    <List>
    <ListToolbar />
        <Datagrid rowClick="edit">
        <TextField source="id" label="Address ID" />
            <TextField source="user_id" label="User ID" />
            <TextField source="recipient_name" label="Recipient Name" />
            <TextField source="address_line1" label="Address Line 1" />
            <TextField source="address_line2" label="Address Line 2" />
            <TextField source="city" label="City" />
            <TextField source="state" label="State" />
            <TextField source="postal_code" label="Postal Code" />
            <TextField source="country" label="Country" />
        </Datagrid>
    </List>
);

export default Adresslist;