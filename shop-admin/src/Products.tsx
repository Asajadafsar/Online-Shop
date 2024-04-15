import * as React from 'react';
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
    DeleteButton,
    Pagination,
    FilterForm,
    ImageField
} from 'react-admin';
import { Stack } from '@mui/material';
const ProductFilters = [
    <TextInput label="Search" source="name" alwaysOn />,
    <TextInput label="Name" source="name" defaultValue="" />,
    // <TextInput label="Category ID" source="category_id" defaultValue="" />
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={ProductFilters} />
        <div>
            <FilterButton filters={ProductFilters} />
           
        </div>
    </Stack>
)

export const ProductsList = (props: any) => (
    <List>
    <ListToolbar />
        <Datagrid rowClick="edit">
            <TextField source="id" label="ID" />
            <TextField source="name" label="Name" />
            <NumberField source="price" label="Price" options={{ style: 'currency', currency: 'USD' }} />
            <TextField source="description" label="Description" />
            <TextField source="category_id" label="Category ID" />
            <ImageField source="image" label="Image" />
            <DeleteButton  /> {/* دکمه حذف بدون قابل بازگشت */}
        </Datagrid>
    </List>
);

