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
    <SearchInput source="action" alwaysOn />,
    <TextInput label="action" source="action"  resettable />,
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={CustomerFilters} />
        <div>
            <FilterButton filters={CustomerFilters} />
           
        </div>
    </Stack>
)
export const logsList = () => (
    <List>
    <ListToolbar />
        <Datagrid rowClick="edit">
            <TextField source="id" label="ID" />
            <TextField source="user_id" label="user_id" />
            <TextField source="action" label="action" />
            <TextField source="action_date" label="action_date" />
            <TextField source="ip_address" label="ip_address" />
        </Datagrid>
    </List>
);

export default logsList;