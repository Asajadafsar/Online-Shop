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
    <SearchInput source="username" alwaysOn />,
    <TextInput label="Email" source="email"  resettable />,
    <TextInput label="username" source="username"  resettable />,
    <TextInput label="phone_number" source="phone_number"  resettable />,
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={CustomerFilters} />
        <div>
            <FilterButton filters={CustomerFilters} />
           
        </div>
    </Stack>
)
export const CustomersList = () => (
    <List>
    <ListToolbar />
        <Datagrid rowClick="edit">
            <TextField source="id" label="ID" />
            <TextField source="username" label="Username" />
            <TextField source="email" label="Email" />
            <TextField source="role" label="Role" />
            <TextField source="phone_number" label="Phone" />
            <TextField source="registration_date" label="Registration Date" />
        </Datagrid>
    </List>
);

export default CustomersList;