


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
    required
} from 'react-admin';
import { Stack } from '@mui/material';
// تعریف فیلترها
const ProductFilters = [
    <TextInput label="Search" source="name" alwaysOn />,
    <TextInput label="Name" source="name" defaultValue="" />,
   
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={ProductFilters} />
        <div>
            <FilterButton filters={ProductFilters} />
           
        </div>
    </Stack>
)

export const CategoryEdit = (props: any) => (
    <Edit {...props} undoable={false}>
        <SimpleForm>
            <TextInput disabled source="id" label="ID" />
            <TextInput source="name" label="Name" validate={required()} />
            <TextInput multiline source="description" label="Description" validate={required()} />
            <NumberInput source="parent_category_id" label="Parent Category ID" />
            <DateInput source="created_at" label="Creation Date" />
        </SimpleForm>
    </Edit>
);
export const CategoryShow = (props: any) => (
    <Show {...props}>
        <SimpleShowLayout>
            <TextField source="id" label="ID" />
            <TextField source="name" label="Name" />
            <TextField source="description" label="Description" />
            <TextField source="parent_category_id" label="Parent Category ID" />
            <DateField source="created_at" label="Creation Date" />
        </SimpleShowLayout>
    </Show>
);
// کامپوننت لیست محصولات
export const CategoryList = (props: any) => (
    <List>
    <ListToolbar />
        <Datagrid rowClick="edit">
        <TextField source="id" label="ID" />
            <TextField source="name" label="Name" />
            <TextField source="description" label="Description" />
            <NumberField source="parent_category_id" label="Parent Category ID" />
            <TextField source="created_at" label="Creation Date" />
        </Datagrid>
    </List>
);
